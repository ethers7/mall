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

/**
 * Oss对象存储管理Service实现类
 * Created by macro on 2018/5/17.
 */
@Service
public class OssServiceImpl implements OssService {

	private static final Logger LOGGER = LoggerFactory.getLogger(OssServiceImpl.class);
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
		// filename/size/mimeType 是阿里云OSS回调body模板中始终会填充的字段（见policy()中callbackBody配置），
		// 对任意成功的对象上传都一定存在合法取值；因此一旦校验失败即可判定回调被伪造或被篡改，
		// 直接拒绝处理（抛出ApiException由GlobalExceptionHandler转为失败响应），而不是静默降级继续执行。
		String filename = sanitizeFilename(request.getParameter("filename"));
		if (filename.isEmpty()) {
			Asserts.fail("OSS回调文件名非法或缺失，已拒绝处理");
		}
		String size = validatePositiveLong(request.getParameter("size"));
		if (size == null) {
			Asserts.fail("OSS回调文件大小参数非法或缺失，已拒绝处理");
		}
		String mimeType = validateMimeType(request.getParameter("mimeType"));
		if (mimeType == null) {
			Asserts.fail("OSS回调mimeType参数非法或缺失，已拒绝处理");
		}
		// width/height 来自回调模板中的${imageInfo.width}/${imageInfo.height}，仅当上传对象是OSS可识别的图片格式时
		// 才会被填充为有效数值；非图片类对象（如视频、文档等本系统也通过同一回调上传的文件）上传成功时这两个字段
		// 本身就不会有合法取值。因此对这两个字段沿用“非法值归一化为null”的降级处理而非整体拒绝回调，
		// 避免把非图片类正常上传误判为非法请求而拒绝——这与filename/size/mimeType的拒绝策略不同，是刻意的设计取舍。
		String width = validatePositiveLong(request.getParameter("width"));
		String height = validatePositiveLong(request.getParameter("height"));
		filename = "http://".concat(ALIYUN_OSS_BUCKET_NAME).concat(".").concat(ALIYUN_OSS_ENDPOINT).concat("/").concat(filename);
		result.setFilename(filename);
		result.setSize(size);
		result.setMimeType(mimeType);
		result.setWidth(width);
		result.setHeight(height);
		return result;
	}

	/**
	 * 校验回调传入的文件名，防止路径穿越等非法字符
	 */
	private String sanitizeFilename(String filename) {
		if (filename == null || filename.isEmpty() || filename.length() > 255) {
			return "";
		}
		if (filename.contains("..") || filename.contains("/") || filename.contains("\\")) {
			LOGGER.warn("OSS回调文件名包含非法字符，已拒绝：{}", filename);
			return "";
		}
		if (!filename.matches("[a-zA-Z0-9._-]+")) {
			LOGGER.warn("OSS回调文件名格式非法，已拒绝：{}", filename);
			return "";
		}
		return filename;
	}

	/**
	 * 校验回调传入的数值型参数（size/width/height），非合法非负整数时返回null
	 */
	private String validatePositiveLong(String value) {
		if (value == null || !value.matches("\\d{1,18}")) {
			return null;
		}
		return value;
	}

	/**
	 * 校验回调传入的mimeType，必须满足type/subtype的基本格式
	 */
	private String validateMimeType(String mimeType) {
		if (mimeType == null || !mimeType.matches("[a-zA-Z0-9.+-]+/[a-zA-Z0-9.+-]+")) {
			return null;
		}
		return mimeType;
	}

}
