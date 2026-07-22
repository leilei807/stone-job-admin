package com.xxl.job.admin.business.controller;

import com.xxl.job.admin.business.mapper.XxlJobInfoMapper;
import com.xxl.job.admin.business.mapper.XxlJobLogMapper;
import com.xxl.job.admin.business.model.XxlJobInfo;
import com.xxl.job.admin.business.model.XxlJobLog;
import com.xxl.job.admin.business.model.dto.XxlJobLogDTO;
import com.xxl.sso.core.helper.XxlSsoHelper;
import com.xxl.sso.core.model.LoginInfo;
import com.xxl.tool.response.Response;
import jakarta.annotation.Resource;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Stone 扩展只读查询端点（新增文件，不改动任何原有 controller）。
 * <p>
 * 标准 xxl-job 与本项目 admin fork 的任务/日志控制器均只有「列表 + 增删改启停」，
 * 没有单条记录的「get」端点；而 Stone 后端 {@code XxlJobAdminClient} 的
 * {@code callTaskGet} / {@code callLogGet} 需要按 id 拉取单条详情
 * （任务详情回显、实时调度状态同步、日志详情页）。
 * <p>
 * 鉴权由 {@code MachineAuthFilter}（Bearer clientToken 前置解析）注入登录态
 * （request 属性 xxl_sso_user），本控制器仅做登录态断言。
 *
 * @author stone
 */
@Controller
public class StoneJobReadController {

    @Resource
    private XxlJobInfoMapper xxlJobInfoMapper;
    @Resource
    private XxlJobLogMapper xxlJobLogMapper;

    /**
     * 按 id 查询单个任务（含实时调度状态 triggerStatus / triggerLastTime / triggerNextTime）
     */
    @RequestMapping("/jobinfo/get")
    @ResponseBody
    public Response<XxlJobInfo> getJobInfo(HttpServletRequest request,
                                          @RequestParam("id") int id) {
        // 登录态断言（MachineAuthFilter 已注入 xxl_sso_user）
        Response<LoginInfo> loginCheck = XxlSsoHelper.loginCheckWithAttr(request);
        if (loginCheck.getCode() != 200) {
            return Response.ofFail(loginCheck.getMsg());
        }
        XxlJobInfo jobInfo = xxlJobInfoMapper.loadById(id);
        if (jobInfo == null) {
            return Response.ofFail("jobinfo not found, id=" + id);
        }
        return Response.ofSuccess(jobInfo);
    }

    /**
     * 按 id 查询单条调度日志
     * 返回 XxlJobLogDTO（与 /joblog/pageList 行视图一致），保证客户端字段映射稳定
     */
    @RequestMapping("/joblog/get")
    @ResponseBody
    public Response<XxlJobLogDTO> getJobLog(HttpServletRequest request,
                                           @RequestParam("id") long id) {
        Response<LoginInfo> loginCheck = XxlSsoHelper.loginCheckWithAttr(request);
        if (loginCheck.getCode() != 200) {
            return Response.ofFail(loginCheck.getMsg());
        }
        XxlJobLog jobLog = xxlJobLogMapper.load(id);
        if (jobLog == null) {
            return Response.ofFail("joblog not found, id=" + id);
        }
        return Response.ofSuccess(new XxlJobLogDTO(jobLog));
    }
}
