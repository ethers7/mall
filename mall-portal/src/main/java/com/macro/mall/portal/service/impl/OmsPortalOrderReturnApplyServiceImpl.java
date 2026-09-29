package com.macro.mall.portal.service.impl;

import com.macro.mall.common.exception.Asserts;
import com.macro.mall.mapper.OmsOrderMapper;
import com.macro.mall.mapper.OmsOrderReturnApplyMapper;
import com.macro.mall.model.OmsOrder;
import com.macro.mall.model.OmsOrderReturnApply;
import com.macro.mall.model.UmsMember;
import com.macro.mall.portal.domain.OmsOrderReturnApplyParam;
import com.macro.mall.portal.service.OmsPortalOrderReturnApplyService;
import com.macro.mall.portal.service.UmsMemberService;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Date;

/**
 * 订单退货管理Service实现类
 * Created by macro on 2018/10/17.
 */
@Service
public class OmsPortalOrderReturnApplyServiceImpl implements OmsPortalOrderReturnApplyService {
    @Autowired
    private OmsOrderReturnApplyMapper returnApplyMapper;
    @Autowired
    private OmsOrderMapper orderMapper;
    @Autowired
    private UmsMemberService memberService;
    @Override
    public int create(OmsOrderReturnApplyParam returnApply) {
        UmsMember member = memberService.getCurrentMember();
        // Validate that the referenced order belongs to the current member
        if (returnApply.getOrderId() != null) {
            OmsOrder order = orderMapper.selectByPrimaryKey(returnApply.getOrderId());
            if (order == null || !member.getId().equals(order.getMemberId())) {
                Asserts.fail("不能对他人订单申请退货！");
            }
        }
        OmsOrderReturnApply realApply = new OmsOrderReturnApply();
        BeanUtils.copyProperties(returnApply,realApply);
        realApply.setCreateTime(new Date());
        realApply.setStatus(0);
        // Set member username from authenticated session, not user input
        realApply.setMemberUsername(member.getUsername());
        return returnApplyMapper.insert(realApply);
    }
}
