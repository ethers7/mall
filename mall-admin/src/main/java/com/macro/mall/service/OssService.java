package com.macro.mall.service;

import com.macro.mall.dto.OssCallbackRequest;
import com.macro.mall.dto.OssCallbackResult;
import com.macro.mall.dto.OssPolicyResult;

/**
 * Oss对象存储管理Service
 * Created by macro on 2018/5/17.
 */
public interface OssService {
    /**
     * Oss上传策略生成
     */
    OssPolicyResult policy();
    /**
     * Oss上传成功回调，入参已在Controller边界完成绑定和校验，不再接收原始请求
     */
    OssCallbackResult callback(OssCallbackRequest callbackRequest);
}
