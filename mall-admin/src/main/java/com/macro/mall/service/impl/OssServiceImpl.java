package com.macro.mall.service.impl;

import cn.hutool.json.JSONUtil;
import com.aliyun.oss.OSSClient;
import com.aliyun.oss.common.utils.BinaryUtil;
import com.aliyun.oss.model.MatchMode;
import com.aliyun.oss.model.PolicyConditions;
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
	// 回调参数白名单校验：文件名仅允许字母、数字、点、横线、下划线及路径分隔符，且不允许目录穿越
	private static final Pattern SAFE_FILENAME_PATTERN = Pattern.compile("^[A-Za-z0-9._\\-/]+$");
	// 回调参数白名单校验：宽高、大小必须为数字
	private static final Pattern NUMERIC_PATTERN = Pattern.compile("^\\d+$");
	// 回调参数白名单校验：mimeType必须符合type/subtype的格式
	private static final Pattern MIME_TYPE_PATTERN = Pattern.compile("^[\\w.+-]+/[\\w.+-]+$");
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
		String filename = sanitizeFilename(request.getParameter("filename"));
		filename = "http://".concat(ALIYUN_OSS_BUCKET_NAME).concat(".").concat(ALIYUN_OSS_ENDPOINT).concat("/").concat(filename);
		result.setFilename(filename);
		result.setSize(sanitizeNumeric(request.getParameter("size")));
		result.setMimeType(sanitizeMimeType(request.getParameter("mimeType")));
		result.setWidth(sanitizeNumeric(request.getParameter("width")));
		result.setHeight(sanitizeNumeric(request.getParameter("height")));
		return result;
	}

	/**
	 * 校验OSS回调传入的filename，拒绝空值、目录穿越及非法字符，避免拼接出恶意的回调地址
	 */
	private String sanitizeFilename(String filename) {
		if (filename == null || filename.isEmpty() || filename.contains("..")
				|| !SAFE_FILENAME_PATTERN.matcher(filename).matches()) {
			LOGGER.warn("Oss回调参数filename校验未通过，已忽略：{}", filename);
			return "";
		}
		return filename;
	}

	/**
	 * 校验OSS回调传入的size/width/height，仅允许数字，避免非数字内容被当做合法元数据存储
	 */
	private String sanitizeNumeric(String value) {
		if (value == null || !NUMERIC_PATTERN.matcher(value).matches()) {
			LOGGER.warn("Oss回调数字型参数校验未通过，已忽略：{}", value);
			return null;
		}
		return value;
	}

	/**
	 * 校验OSS回调传入的mimeType，必须符合type/subtype格式
	 */
	private String sanitizeMimeType(String mimeType) {
		if (mimeType == null || !MIME_TYPE_PATTERN.matcher(mimeType).matches()) {
			LOGGER.warn("Oss回调参数mimeType校验未通过，已忽略：{}", mimeType);
			return null;
		}
		return mimeType;
	}

}
