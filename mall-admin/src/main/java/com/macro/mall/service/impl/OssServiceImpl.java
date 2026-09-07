package com.macro.mall.service.impl;

import cn.hutool.json.JSONUtil;
import com.aliyun.oss.OSSClient;
import com.aliyun.oss.common.utils.BinaryUtil;
import com.aliyun.oss.model.MatchMode;
import com.aliyun.oss.model.PolicyConditions;
import com.macro.mall.common.exception.Asserts;
import com.macro.mall.dto.OssCallbackParam;
import com.macro.mall.dto.OssCallbackRequest;
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
	 * OSS上传成功回调参数的校验规则，OSS的object key最长1024个字符
	 */
	private static final int MAX_OBJECT_KEY_LENGTH = OssCallbackRequest.MAX_OBJECT_KEY_LENGTH;
	private static final int MAX_MIME_TYPE_LENGTH = OssCallbackRequest.MAX_MIME_TYPE_LENGTH;
	private static final Pattern OBJECT_KEY_PATTERN = Pattern.compile(OssCallbackRequest.OBJECT_KEY_REGEX);
	private static final Pattern SIZE_PATTERN = Pattern.compile(OssCallbackRequest.SIZE_REGEX);
	private static final Pattern MIME_TYPE_PATTERN = Pattern.compile(OssCallbackRequest.MIME_TYPE_REGEX);
	private static final Pattern DIMENSION_PATTERN = Pattern.compile(OssCallbackRequest.DIMENSION_REGEX);
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
	public OssCallbackResult callback(OssCallbackRequest callbackRequest) {
		OssCallbackResult result= new OssCallbackResult();
		// 回调参数来自外部请求，已在Controller层完成绑定校验，此处再次校验保证任何调用方都无法绕过
		if (callbackRequest == null) {
			Asserts.fail("上传回调参数不能为空");
		}
		String objectKey = validateObjectKey(callbackRequest.getFilename());
		String filename = "http://".concat(ALIYUN_OSS_BUCKET_NAME).concat(".").concat(ALIYUN_OSS_ENDPOINT).concat("/").concat(objectKey);
		result.setFilename(filename);
		result.setSize(validateSize(callbackRequest.getSize()));
		result.setMimeType(validateMimeType(callbackRequest.getMimeType()));
		result.setWidth(validateImageDimension(callbackRequest.getWidth(), "width"));
		result.setHeight(validateImageDimension(callbackRequest.getHeight(), "height"));
		return result;
	}

	/**
	 * 校验上传成功回调的文件路径（OSS的object key）
	 * 仅允许白名单字符、限制长度、拒绝目录穿越，并且必须位于签名策略允许的上传目录下
	 */
	private String validateObjectKey(String objectKey) {
		if (objectKey == null || objectKey.isEmpty()) {
			Asserts.fail("上传回调参数filename不能为空");
		}
		if (objectKey.length() > MAX_OBJECT_KEY_LENGTH || !OBJECT_KEY_PATTERN.matcher(objectKey).matches()) {
			Asserts.fail("上传回调参数filename不合法");
		}
		// 拒绝绝对路径、空路径段以及目录穿越
		if (objectKey.startsWith("/") || objectKey.endsWith("/") || objectKey.contains("//")) {
			Asserts.fail("上传回调参数filename不合法");
		}
		for (String segment : objectKey.split("/")) {
			if (".".equals(segment) || "..".equals(segment)) {
				Asserts.fail("上传回调参数filename不合法");
			}
		}
		// 只接受签名策略中允许的上传目录前缀
		if (!objectKey.startsWith(ALIYUN_OSS_DIR_PREFIX)) {
			Asserts.fail("上传回调参数filename不在允许的上传目录内");
		}
		return objectKey;
	}

	/**
	 * 校验上传成功回调的文件大小，必须为数字且不超过签名策略允许的最大值
	 */
	private String validateSize(String size) {
		if (size == null || !SIZE_PATTERN.matcher(size).matches()) {
			Asserts.fail("上传回调参数size不合法");
		}
		long maxSize = (long) ALIYUN_OSS_MAX_SIZE * 1024 * 1024;
		if (Long.parseLong(size) > maxSize) {
			Asserts.fail("上传文件大小超出限制");
		}
		return size;
	}

	/**
	 * 校验上传成功回调的mimeType，非图片文件时OSS可能不回传该参数
	 */
	private String validateMimeType(String mimeType) {
		if (mimeType == null || mimeType.isEmpty()) {
			return mimeType;
		}
		if (mimeType.length() > MAX_MIME_TYPE_LENGTH || !MIME_TYPE_PATTERN.matcher(mimeType).matches()) {
			Asserts.fail("上传回调参数mimeType不合法");
		}
		return mimeType;
	}

	/**
	 * 校验图片的宽高，非图片文件时OSS可能不回传该参数
	 */
	private String validateImageDimension(String dimension, String paramName) {
		if (dimension == null || dimension.isEmpty()) {
			return dimension;
		}
		if (!DIMENSION_PATTERN.matcher(dimension).matches()) {
			Asserts.fail("上传回调参数" + paramName + "不合法");
		}
		return dimension;
	}

}
