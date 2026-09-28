package com.macro.mall.service.impl;

import cn.hutool.core.util.StrUtil;
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
	// 文件名允许的字符：字母、数字、点、下划线、中划线、斜杠（子目录），且不允许出现".."路径穿越
	private static final Pattern SAFE_FILENAME_PATTERN = Pattern.compile("^[a-zA-Z0-9._\\-/]+$");
	// 非负整数，用于校验size、width、height
	private static final Pattern NUMERIC_PATTERN = Pattern.compile("^\\d+$");
	// 基本的MimeType格式校验，如image/jpeg
	private static final Pattern MIME_TYPE_PATTERN = Pattern.compile("^[\\w.+-]+/[\\w.+-]+$");
	private static final String DEFAULT_MIME_TYPE = "application/octet-stream";
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
		String filename = request.getParameter("filename");
		if (isSafeFilename(filename)) {
			filename = "http://".concat(ALIYUN_OSS_BUCKET_NAME).concat(".").concat(ALIYUN_OSS_ENDPOINT).concat("/").concat(filename);
			result.setFilename(filename);
		} else {
			LOGGER.warn("OSS回调中filename参数校验失败，已忽略：{}", filename);
		}
		result.setSize(sanitizeNumeric(request.getParameter("size")));
		result.setMimeType(sanitizeMimeType(request.getParameter("mimeType")));
		result.setWidth(sanitizeNumeric(request.getParameter("width")));
		result.setHeight(sanitizeNumeric(request.getParameter("height")));
		return result;
	}

	/**
	 * 校验文件名是否安全：非空、不含路径穿越（..）且仅包含允许的字符
	 */
	private boolean isSafeFilename(String filename) {
		if (StrUtil.isBlank(filename)) {
			return false;
		}
		if (filename.contains("..") || filename.startsWith("/")) {
			return false;
		}
		return SAFE_FILENAME_PATTERN.matcher(filename).matches();
	}

	/**
	 * 校验数值型参数（size、width、height），非负整数格式才返回原值，否则返回默认值"0"
	 */
	private String sanitizeNumeric(String value) {
		if (StrUtil.isNotBlank(value) && NUMERIC_PATTERN.matcher(value).matches()) {
			return value;
		}
		return "0";
	}

	/**
	 * 校验mimeType是否符合类似"type/subtype"的基本格式，否则返回安全默认值
	 */
	private String sanitizeMimeType(String mimeType) {
		if (StrUtil.isNotBlank(mimeType) && MIME_TYPE_PATTERN.matcher(mimeType).matches()) {
			return mimeType;
		}
		return DEFAULT_MIME_TYPE;
	}

}
