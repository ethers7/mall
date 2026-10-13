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
	// 简单校验mimeType是否符合"type/subtype"格式
	private static final Pattern MIME_TYPE_PATTERN =
			Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9!#$&^_.+-]*/[a-zA-Z0-9][a-zA-Z0-9!#$&^_.+-]*$");
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
		result.setSize(sanitizeNumericParam(request.getParameter("size")));
		result.setMimeType(sanitizeMimeType(request.getParameter("mimeType")));
		result.setWidth(sanitizeNumericParam(request.getParameter("width")));
		result.setHeight(sanitizeNumericParam(request.getParameter("height")));
		return result;
	}

	/**
	 * 校验OSS回调中的filename参数，拒绝空值及路径穿越、非法分隔符等异常输入
	 */
	private String sanitizeFilename(String filename) {
		if (filename == null || filename.trim().isEmpty()) {
			LOGGER.warn("OSS回调中filename参数为空");
			return "";
		}
		filename = filename.trim();
		if (filename.contains("..") || filename.contains("\\")) {
			LOGGER.warn("OSS回调中filename参数包含非法字符，已拒绝：{}", filename);
			return "";
		}
		// 去除开头多余的"/"，避免拼接出协议相对或绝对路径
		while (filename.startsWith("/")) {
			filename = filename.substring(1);
		}
		return filename;
	}

	/**
	 * 校验OSS回调中的mimeType参数是否符合"type/subtype"格式
	 */
	private String sanitizeMimeType(String mimeType) {
		if (mimeType == null || !MIME_TYPE_PATTERN.matcher(mimeType.trim()).matches()) {
			LOGGER.warn("OSS回调中mimeType参数格式非法：{}", mimeType);
			return "";
		}
		return mimeType.trim();
	}

	/**
	 * 校验OSS回调中的数值类参数（size/width/height），非法输入时回退为"0"
	 */
	private String sanitizeNumericParam(String value) {
		if (value == null || !value.trim().matches("\\d+")) {
			LOGGER.warn("OSS回调中数值参数格式非法：{}", value);
			return "0";
		}
		return value.trim();
	}

}
