package com.macro.mall.service;

import com.macro.mall.dto.OssCallbackRequestParam;
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
     * Oss上传成功回调
     *
     * @param callbackParam 已在Controller层完成校验的回调参数
     */
    OssCallbackResult callback(OssCallbackRequestParam callbackParam);
}
