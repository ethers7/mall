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
	// 校验回调参数：文件名不允许出现路径穿越或非常规字符，长度受限
	private static final Pattern SAFE_FILENAME_PATTERN = Pattern.compile("^[A-Za-z0-9_\\-./]{1,255}$");
	// 校验回调参数：mimeType 必须符合 type/subtype 格式
	private static final Pattern SAFE_MIME_TYPE_PATTERN = Pattern.compile("^[A-Za-z0-9!#$&^_.+-]{1,64}/[A-Za-z0-9!#$&^_.+-]{1,64}$");
	// 校验回调参数：size/width/height 必须为非负整数，长度受限，避免异常/超大数值
	private static final Pattern SAFE_NUMERIC_PATTERN = Pattern.compile("^[0-9]{1,10}$");
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
		if (filename == null) {
			LOGGER.warn("OSS回调参数filename校验失败，已拒绝处理");
			return result;
		}
		filename = "http://".concat(ALIYUN_OSS_BUCKET_NAME).concat(".").concat(ALIYUN_OSS_ENDPOINT).concat("/").concat(filename);
		result.setFilename(filename);
		result.setSize(sanitizeNumeric(request.getParameter("size")));
		result.setMimeType(sanitizeMimeType(request.getParameter("mimeType")));
		result.setWidth(sanitizeNumeric(request.getParameter("width")));
		result.setHeight(sanitizeNumeric(request.getParameter("height")));
		return result;
	}

	/**
	 * 校验OSS回调文件名：拒绝空值、路径穿越序列(..)、反斜杠以及不在安全字符集内的内容
	 */
	private String sanitizeFilename(String filename) {
		if (filename == null || filename.isEmpty() || filename.contains("..") || filename.contains("\\")) {
			return null;
		}
		if (!SAFE_FILENAME_PATTERN.matcher(filename).matches()) {
			return null;
		}
		return filename;
	}

	/**
	 * 校验OSS回调mimeType：必须符合 type/subtype 的合法格式
	 */
	private String sanitizeMimeType(String mimeType) {
		if (mimeType == null || !SAFE_MIME_TYPE_PATTERN.matcher(mimeType).matches()) {
			return null;
		}
		return mimeType;
	}

	/**
	 * 校验OSS回调数值型参数(size/width/height)：必须为非负整数
	 */
	private String sanitizeNumeric(String value) {
		if (value == null || !SAFE_NUMERIC_PATTERN.matcher(value).matches()) {
			return null;
		}
		return value;
	}

}
