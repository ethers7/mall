package com.macro.mall.service.impl;

import cn.hutool.core.util.StrUtil;
import cn.hutool.json.JSONUtil;
import com.aliyun.oss.OSSClient;
import com.aliyun.oss.common.utils.BinaryUtil;
import com.aliyun.oss.model.MatchMode;
import com.aliyun.oss.model.PolicyConditions;
import com.macro.mall.common.exception.Asserts;
import com.macro.mall.dto.OssCallbackParam;
import com.macro.mall.dto.OssCallbackResult;
import com.macro.mall.dto.OssPolicyResult;
import com.macro.mall.service.OssService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import jakarta.servlet.http.HttpServletRequest;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.regex.Pattern;

/**
 * Oss对象存储管理Service实现类
 * Created by macro on 2018/5/17.
 */
@Service
public class OssServiceImpl implements OssService {

	private static final Logger LOGGER = LoggerFactory.getLogger(OssServiceImpl.class);
	/**
	 * 回调中OSS对象名称的白名单格式：只允许字母、数字、常见文件名符号及目录分隔符，
	 * 不允许出现路径穿越（..）、反斜杠、协议分隔符及URL特殊字符，长度上限与OSS对象名称一致
	 */
	private static final Pattern OSS_OBJECT_NAME_PATTERN = Pattern.compile("^[\\p{L}\\p{N}][\\p{L}\\p{N}\\-._/() ]{0,1022}$");
	/**
	 * 回调中mimeType的白名单格式，如image/jpeg
	 */
	private static final Pattern MIME_TYPE_PATTERN = Pattern.compile("^[\\p{Alnum}][\\p{Alnum}!#$&^_.+-]{0,63}/[\\p{Alnum}][\\p{Alnum}!#$&^_.+-]{0,63}$");
	/**
	 * 回调中数字类参数（文件大小、图片宽高）的白名单格式
	 */
	private static final Pattern NUMERIC_PATTERN = Pattern.compile("^\\p{Digit}{1,19}$");

	@Value("${aliyun.oss.policy.expire}")
	private int ALIYUN_OSS_EXPIRE;
	@Value("${aliyun.oss.maxSize}")
	private int ALIYUN_OSS_MAX_SIZE;
	@Value("${aliyun.oss.callback}")
	private String ALIYUN_OSS_CALLBACK;
	@Value("${aliyun.oss.bucketName}")
	private String ALIYUN_OSS_BUCKET_NAME;
	@Value("${aliyun.oss.endpoint}")
	private String ALIYUN_OSS_ENDPOINT;
	@Value("${aliyun.oss.dir.prefix}")
	private String ALIYUN_OSS_DIR_PREFIX;

	@Autowired
	private OSSClient ossClient;

	/**
	 * 签名生成
	 */
	@Override
	public OssPolicyResult policy() {
		OssPolicyResult result = new OssPolicyResult();
		// 存储目录
		SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMdd");
		String dir = ALIYUN_OSS_DIR_PREFIX+sdf.format(new Date());
		// 签名有效期
		long expireEndTime = System.currentTimeMillis() + ALIYUN_OSS_EXPIRE * 1000;
		Date expiration = new Date(expireEndTime);
		// 文件大小
		long maxSize = ALIYUN_OSS_MAX_SIZE * 1024 * 1024;
		// 回调
		OssCallbackParam callback = new OssCallbackParam();
		callback.setCallbackUrl(ALIYUN_OSS_CALLBACK);
		callback.setCallbackBody("filename=${object}&size=${size}&mimeType=${mimeType}&height=${imageInfo.height}&width=${imageInfo.width}");
		callback.setCallbackBodyType("application/x-www-form-urlencoded");
		// 提交节点
		String action = "http://" + ALIYUN_OSS_BUCKET_NAME + "." + ALIYUN_OSS_ENDPOINT;
		try {
			PolicyConditions policyConds = new PolicyConditions();
			policyConds.addConditionItem(PolicyConditions.COND_CONTENT_LENGTH_RANGE, 0, maxSize);
			policyConds.addConditionItem(MatchMode.StartWith, PolicyConditions.COND_KEY, dir);
			String postPolicy = ossClient.generatePostPolicy(expiration, policyConds);
			byte[] binaryData = postPolicy.getBytes("utf-8");
			String policy = BinaryUtil.toBase64String(binaryData);
			String signature = ossClient.calculatePostSignature(postPolicy);
			String callbackData = BinaryUtil.toBase64String(JSONUtil.parse(callback).toString().getBytes("utf-8"));
			// 返回结果
			result.setAccessKeyId(ossClient.getCredentialsProvider().getCredentials().getAccessKeyId());
			result.setPolicy(policy);
			result.setSignature(signature);
			result.setDir(dir);
			result.setCallback(callbackData);
			result.setHost(action);
		} catch (Exception e) {
			LOGGER.error("签名生成失败", e);
		}
		return result;
	}

	@Override
	public OssCallbackResult callback(HttpServletRequest request) {
		OssCallbackResult result= new OssCallbackResult();
		// 回调参数由外部请求传入，均视为不可信数据，需要先校验再使用
		String objectName = validateObjectName(request.getParameter("filename"));
		String filename = "http://".concat(ALIYUN_OSS_BUCKET_NAME).concat(".").concat(ALIYUN_OSS_ENDPOINT).concat("/").concat(objectName);
		result.setFilename(filename);
		result.setSize(validateOptional(request.getParameter("size"), NUMERIC_PATTERN, "size"));
		result.setMimeType(validateOptional(request.getParameter("mimeType"), MIME_TYPE_PATTERN, "mimeType"));
		result.setWidth(validateOptional(request.getParameter("width"), NUMERIC_PATTERN, "width"));
		result.setHeight(validateOptional(request.getParameter("height"), NUMERIC_PATTERN, "height"));
		return result;
	}

	/**
	 * 校验回调传入的OSS对象名称，防止路径穿越及URL拼接注入
	 *
	 * @param objectName 回调中的对象名称（filename参数）
	 * @return 校验通过的对象名称
	 */
	private String validateObjectName(String objectName) {
		if (StrUtil.isBlank(objectName) || objectName.contains("..")
				|| !OSS_OBJECT_NAME_PATTERN.matcher(objectName).matches()) {
			// 不在日志及异常信息中回显非法参数值，避免日志注入
			LOGGER.warn("OSS回调参数filename校验失败！");
			Asserts.fail("OSS回调参数filename不合法！");
		}
		return objectName;
	}

	/**
	 * 校验回调传入的可选参数，为空时返回null，格式非法时直接拒绝该回调
	 *
	 * @param value     回调中的参数值
	 * @param pattern   该参数允许的格式
	 * @param paramName 参数名称，仅用于提示信息
	 * @return 校验通过的参数值，参数未传时返回null
	 */
	private String validateOptional(String value, Pattern pattern, String paramName) {
		if (StrUtil.isBlank(value)) {
			// 非图片文件不会返回图片宽高等信息，此时保持为空
			return null;
		}
		if (!pattern.matcher(value).matches()) {
			LOGGER.warn("OSS回调参数校验失败！参数名称：{}", paramName);
			Asserts.fail("OSS回调参数" + paramName + "不合法！");
		}
		return value;
	}

}
