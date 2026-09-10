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
	// 回调文件名只允许字母、数字及常见路径分隔符/符号，且不允许出现路径穿越序列
	private static final Pattern FILENAME_PATTERN = Pattern.compile("^[A-Za-z0-9][A-Za-z0-9/_.\\-]{0,255}$");
	// 回调mimeType需符合“type/subtype”这种标准MIME类型格式
	private static final Pattern MIME_TYPE_PATTERN = Pattern.compile("^[A-Za-z0-9]+/[A-Za-z0-9.+\\-]+$");
	// 回调中的宽、高、文件大小必须是合法的非负整数
	private static final Pattern NUMERIC_PATTERN = Pattern.compile("^\\d{1,19}$");
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
		if (!isValidFilename(filename)) {
			LOGGER.warn("OSS回调中的filename参数非法，拒绝处理：{}", filename);
			return result;
		}
		filename = "http://".concat(ALIYUN_OSS_BUCKET_NAME).concat(".").concat(ALIYUN_OSS_ENDPOINT).concat("/").concat(filename);
		result.setFilename(filename);

		String size = request.getParameter("size");
		result.setSize(isValidNumeric(size) ? size : null);

		String mimeType = request.getParameter("mimeType");
		result.setMimeType(isValidMimeType(mimeType) ? mimeType : null);

		String width = request.getParameter("width");
		result.setWidth(isValidNumeric(width) ? width : null);

		String height = request.getParameter("height");
		result.setHeight(isValidNumeric(height) ? height : null);
		return result;
	}

	/**
	 * 校验OSS回调中的filename参数，禁止路径穿越及非法字符
	 */
	private boolean isValidFilename(String filename) {
		return filename != null
				&& !filename.contains("..")
				&& FILENAME_PATTERN.matcher(filename).matches();
	}

	/**
	 * 校验OSS回调中的mimeType参数是否符合标准MIME类型格式
	 */
	private boolean isValidMimeType(String mimeType) {
		return mimeType != null && MIME_TYPE_PATTERN.matcher(mimeType).matches();
	}

	/**
	 * 校验OSS回调中的size/width/height参数是否为合法的非负整数
	 */
	private boolean isValidNumeric(String value) {
		return value != null && NUMERIC_PATTERN.matcher(value).matches();
	}

}
