package com.macro.mall.service.impl;

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
	private static final int MAX_FILENAME_LENGTH = 1024;
	private static final Pattern CONTROL_CHARS = Pattern.compile("[\\p{Cntrl}]");
	private static final Pattern NON_NEGATIVE_INTEGER = Pattern.compile("^[0-9]{1,15}$");
	private static final Pattern MIME_TYPE = Pattern.compile("^[A-Za-z0-9!#$&^_.+-]{1,127}/[A-Za-z0-9!#$&^_.+-]{1,127}$");
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
		String filename = validateFilename(request.getParameter("filename"));
		filename = "http://".concat(ALIYUN_OSS_BUCKET_NAME).concat(".").concat(ALIYUN_OSS_ENDPOINT).concat("/").concat(filename);
		result.setFilename(filename);
		result.setSize(validateNumber(request.getParameter("size"), "size"));
		result.setMimeType(validateMimeType(request.getParameter("mimeType")));
		result.setWidth(validateNumber(request.getParameter("width"), "width"));
		result.setHeight(validateNumber(request.getParameter("height"), "height"));
		return result;
	}

	/**
	 * 校验OSS回调的文件对象名：非空、长度受限、无控制字符/反斜杠/路径回退/前导斜杠
	 */
	private static String validateFilename(String filename) {
		if (filename == null || filename.isEmpty() || filename.length() > MAX_FILENAME_LENGTH
				|| filename.startsWith("/") || filename.indexOf('\\') >= 0
				|| CONTROL_CHARS.matcher(filename).find()) {
			Asserts.fail("非法的filename参数");
		}
		for (String segment : filename.split("/", -1)) {
			if ("..".equals(segment) || ".".equals(segment)) {
				Asserts.fail("非法的filename参数");
			}
		}
		return filename;
	}

	/**
	 * 校验数值参数：为空（如非图片文件无宽高）则原样返回，否则必须是有界的非负整数
	 */
	private static String validateNumber(String value, String name) {
		if (value == null || value.isEmpty()) {
			return value;
		}
		if (!NON_NEGATIVE_INTEGER.matcher(value).matches()) {
			Asserts.fail("非法的" + name + "参数");
		}
		return value;
	}

	/**
	 * 校验mimeType格式：type/subtype
	 */
	private static String validateMimeType(String mimeType) {
		if (mimeType == null || !MIME_TYPE.matcher(mimeType).matches()) {
			Asserts.fail("非法的mimeType参数");
		}
		return mimeType;
	}

}
