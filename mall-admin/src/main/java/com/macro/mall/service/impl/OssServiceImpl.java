package com.macro.mall.service.impl;

import cn.hutool.core.util.StrUtil;
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
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Oss对象存储管理Service实现类
 * Created by macro on 2018/5/17.
 */
@Service
public class OssServiceImpl implements OssService {

	private static final Logger LOGGER = LoggerFactory.getLogger(OssServiceImpl.class);
	/**
	 * 上传回调中对象名（文件名）的最大长度，与绑定层的校验规则保持一致
	 */
	private static final int MAX_FILENAME_LENGTH = OssCallbackRequest.MAX_FILENAME_LENGTH;
	/**
	 * 对象名白名单：只允许字母、数字、下划线、中划线、点号和目录分隔符，且必须以字母或数字开头
	 */
	private static final Pattern FILENAME_PATTERN = Pattern.compile(OssCallbackRequest.FILENAME_REGEX);
	/**
	 * 允许上传的文件扩展名白名单
	 */
	private static final Set<String> ALLOWED_FILENAME_EXTENSIONS = Set.of(
			"jpg", "jpeg", "png", "gif", "bmp", "webp", "ico", "tif", "tiff");
	/**
	 * 数字类型回调参数白名单（文件大小、图片宽高）
	 */
	private static final Pattern NUMERIC_PATTERN = Pattern.compile(OssCallbackRequest.NUMERIC_REGEX);
	/**
	 * mimeType白名单，形如image/jpeg
	 */
	private static final Pattern MIME_TYPE_PATTERN = Pattern.compile(OssCallbackRequest.MIME_TYPE_REGEX);

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
		// 回调参数已由Controller边界绑定并校验，此处再做一次失败关闭的校验后才允许使用
		if (callbackRequest == null) {
			Asserts.fail("上传回调参数不能为空");
		}
		OssCallbackResult result= new OssCallbackResult();
		String filename = validateFilename(callbackRequest.getFilename());
		filename = "http://".concat(ALIYUN_OSS_BUCKET_NAME).concat(".").concat(ALIYUN_OSS_ENDPOINT).concat("/").concat(filename);
		result.setFilename(filename);
		result.setSize(validateNumeric(callbackRequest.getSize(), "文件大小"));
		result.setMimeType(validateMimeType(callbackRequest.getMimeType()));
		result.setWidth(validateNumeric(callbackRequest.getWidth(), "图片宽度"));
		result.setHeight(validateNumeric(callbackRequest.getHeight(), "图片高度"));
		return result;
	}

	/**
	 * 校验上传回调中的对象名（文件名）：只允许白名单字符、拒绝路径穿越，
	 * 且必须位于签名允许的上传目录下、扩展名在白名单内。
	 */
	private String validateFilename(String filename) {
		if (StrUtil.isEmpty(filename) || filename.length() > MAX_FILENAME_LENGTH) {
			Asserts.fail("上传文件名不能为空且长度不能超过" + MAX_FILENAME_LENGTH);
		}
		if (!FILENAME_PATTERN.matcher(filename).matches()) {
			Asserts.fail("上传文件名包含非法字符");
		}
		// 拒绝路径穿越及非规范路径
		if (filename.contains("..") || filename.contains("//") || filename.endsWith("/")) {
			Asserts.fail("上传文件名包含非法路径");
		}
		// 只接受本次签名允许的上传目录下的文件
		if (StrUtil.isNotEmpty(ALIYUN_OSS_DIR_PREFIX) && !filename.startsWith(ALIYUN_OSS_DIR_PREFIX)) {
			Asserts.fail("上传文件不在允许的上传目录下");
		}
		int dotIndex = filename.lastIndexOf('.');
		int separatorIndex = filename.lastIndexOf('/');
		String extension = dotIndex > separatorIndex + 1 ? filename.substring(dotIndex + 1).toLowerCase(Locale.ROOT) : "";
		if (!ALLOWED_FILENAME_EXTENSIONS.contains(extension)) {
			Asserts.fail("不支持该类型的上传文件");
		}
		return filename;
	}

	/**
	 * 校验数字类型的回调参数，非图片文件的宽高可能为空，为空时原样返回
	 */
	private String validateNumeric(String value, String paramName) {
		if (StrUtil.isEmpty(value)) {
			return value;
		}
		if (!NUMERIC_PATTERN.matcher(value).matches()) {
			Asserts.fail(paramName + "参数不合法");
		}
		return value;
	}

	/**
	 * 校验mimeType回调参数，为空时原样返回
	 */
	private String validateMimeType(String mimeType) {
		if (StrUtil.isEmpty(mimeType)) {
			return mimeType;
		}
		if (!MIME_TYPE_PATTERN.matcher(mimeType).matches()) {
			Asserts.fail("mimeType参数不合法");
		}
		return mimeType;
	}

}
