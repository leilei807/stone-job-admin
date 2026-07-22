package com.xxl.job.admin.framework.web.casdoor;

import com.xxl.job.admin.framework.mapper.XxlJobUserMapper;
import com.xxl.job.admin.framework.model.XxlJobUser;
import com.xxl.tool.id.UUIDTool;
import jakarta.annotation.Resource;
import org.springframework.stereotype.Component;

/**
 * 按 casdoorUserId 查/建 xxl_job_user。不改 SimpleLoginStore。
 * 经此创建的账号默认角色=管理员(1)：调用方 Stone 已在自身侧完成 job:* 权限校验，
 * 因此能被带到这里的用户都是已授权用户。
 */
@Component
public class CasdoorUserResolver {

	@Resource
	private XxlJobUserMapper xxlJobUserMapper;

	public XxlJobUser resolve(String casdoorUserId) {
		XxlJobUser user = xxlJobUserMapper.loadByUserName(casdoorUserId);
		if (user == null) {
			user = new XxlJobUser();
			user.setUsername(casdoorUserId);
			user.setPassword(UUIDTool.getSimpleUUID()); // 不可登录的随机密码
			user.setRole(1);   // 管理员：已通过 Stone 授权
			user.setPermission("");
			xxlJobUserMapper.save(user);
		}
		return user;
	}
}
