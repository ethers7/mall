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
	// 对象存储key的安全白名单：字母、数字、点、下划线、中划线、斜杠
	private static final Pattern FILENAME_PATTERN = Pattern.compile("^[A-Za-z0-9_\\-./]+$");
	// 基本的MIME类型格式校验
	private static final Pattern MIME_TYPE_PATTERN = Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9!#$&.+\\-^_]*/[a-zA-Z0-9][a-zA-Z0-9!#$&.+\\-^_]*$");
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
		if (isValidFilename(filename)) {
			filename = "http://".concat(ALIYUN_OSS_BUCKET_NAME).concat(".").concat(ALIYUN_OSS_ENDPOINT).concat("/").concat(filename);
			result.setFilename(filename);
		} else {
			LOGGER.warn("OSS回调参数filename校验失败，已忽略：{}", filename);
		}
		result.setSize(validateNonNegativeInteger(request.getParameter("size"), "size"));
		String mimeType = request.getParameter("mimeType");
		if (isValidMimeType(mimeType)) {
			result.setMimeType(mimeType);
		} else {
			LOGGER.warn("OSS回调参数mimeType校验失败，已忽略：{}", mimeType);
		}
		result.setWidth(validateNonNegativeInteger(request.getParameter("width"), "width"));
		result.setHeight(validateNonNegativeInteger(request.getParameter("height"), "height"));
		return result;
	}

	/**
	 * 校验对象存储文件名是否安全：非空、不含路径穿越/控制字符、且匹配安全白名单
	 */
	private boolean isValidFilename(String filename) {
		if (filename == null || filename.isEmpty()) {
			return false;
		}
		if (filename.contains("..") || filename.contains("\n") || filename.contains("\r")) {
			return false;
		}
		return FILENAME_PATTERN.matcher(filename).matches();
	}

	/**
	 * 校验MIME类型格式是否合法
	 */
	private boolean isValidMimeType(String mimeType) {
		return mimeType != null && MIME_TYPE_PATTERN.matcher(mimeType).matches();
	}

	/**
	 * 校验参数是否为非负整数（用于size/width/height），非法则返回null
	 */
	private String validateNonNegativeInteger(String value, String fieldName) {
		if (value == null) {
			return null;
		}
		try {
			long parsed = Long.parseLong(value.trim());
			if (parsed < 0) {
				LOGGER.warn("OSS回调参数{}为负数，已忽略：{}", fieldName, value);
				return null;
			}
			return value;
		} catch (NumberFormatException e) {
			LOGGER.warn("OSS回调参数{}格式非法，已忽略：{}", fieldName, value);
			return null;
		}
	}

}
