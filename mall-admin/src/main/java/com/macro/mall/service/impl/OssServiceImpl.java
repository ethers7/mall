package com.macro.mall.service.impl;

import cn.hutool.core.util.StrUtil;
import cn.hutool.json.JSONUtil;
import com.aliyun.oss.OSSClient;
import com.aliyun.oss.common.utils.BinaryUtil;
import com.aliyun.oss.model.MatchMode;
import com.aliyun.oss.model.PolicyConditions;
import com.macro.mall.common.exception.Asserts;
import com.macro.mall.dto.OssCallbackParam;
import com.macro.mall.dto.OssCallbackRequestParam;
import com.macro.mall.dto.OssCallbackResult;
import com.macro.mall.dto.OssPolicyResult;
import com.macro.mall.service.OssService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

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
	 * 回调参数的白名单格式与{@link OssCallbackRequestParam}上的声明式校验保持一致，
	 * 在Service层再做一次兜底校验，避免绕过Controller直接调用时使用未校验的数据
	 */
	private static final Pattern OSS_OBJECT_NAME_PATTERN = Pattern.compile(OssCallbackRequestParam.OBJECT_NAME_REGEX);
	private static final Pattern MIME_TYPE_PATTERN = Pattern.compile(OssCallbackRequestParam.MIME_TYPE_REGEX);
	private static final Pattern NUMERIC_PATTERN = Pattern.compile(OssCallbackRequestParam.NUMERIC_REGEX);

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
	public OssCallbackResult callback(OssCallbackRequestParam callbackParam) {
		if (callbackParam == null) {
			LOGGER.warn("OSS回调参数缺失！");
			Asserts.fail("OSS回调参数不合法！");
		}
		OssCallbackResult result= new OssCallbackResult();
		// 回调参数已在Controller层通过Bean Validation校验，此处再兜底校验一次后才用于拼接访问地址
		String objectName = validateObjectName(callbackParam.getFilename());
		String filename = "http://".concat(ALIYUN_OSS_BUCKET_NAME).concat(".").concat(ALIYUN_OSS_ENDPOINT).concat("/").concat(objectName);
		result.setFilename(filename);
		result.setSize(validateOptional(callbackParam.getSize(), NUMERIC_PATTERN, "size"));
		result.setMimeType(validateOptional(callbackParam.getMimeType(), MIME_TYPE_PATTERN, "mimeType"));
		result.setWidth(validateOptional(callbackParam.getWidth(), NUMERIC_PATTERN, "width"));
		result.setHeight(validateOptional(callbackParam.getHeight(), NUMERIC_PATTERN, "height"));
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
