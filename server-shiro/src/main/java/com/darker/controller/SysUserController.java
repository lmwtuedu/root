package com.darker.controller;

import com.darker.entity.SysUserEntity;
import com.darker.service.SysUserRoleService;
import com.darker.service.SysUserService;
import com.darker.utils.ShiroUtils;
import com.darker.annotation.SysLog;
import com.darker.entity.SysUserEntity;
import com.darker.service.SysUserRoleService;
import com.darker.service.SysUserService;
import com.darker.utils.*;
import com.darker.validator.group.AddGroup;
import com.darker.validator.group.UpdateGroup;
import com.darker.validator.Assert;
import com.darker.validator.ValidatorUtils;

import org.apache.commons.lang.ArrayUtils;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.crypto.hash.Sha256Hash;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.List;
import java.util.Map;

/**
 * 系统用户
 * 
 * @author chenshun
 * @email sunlightcs@gmail.com
 * @date 2016年10月31日 上午10:40:10
 */
@RestController
@RequestMapping("/sys/user")
public class SysUserController extends AbstractController {

    private static final Logger log = LoggerFactory.getLogger(SysUserController.class);

	@Autowired
	private SysUserService sysUserService;
	@Autowired
	private SysUserRoleService sysUserRoleService;
	
	/**
	 * 所有用户列表
	 */
	@RequestMapping("/list")
	@RequiresPermissions("sys:user:list")
	public R list(@RequestParam Map<String, Object> params){
		//只有超级管理员，才能查看所有管理员列表
		if(getUserId() != Constant.SUPER_ADMIN){
			params.put("createUserId", getUserId());
		}
		
		//查询列表数据
		Query query = new Query(params);
		List<SysUserEntity> userList = sysUserService.queryList(query);
		int total = sysUserService.queryTotal(query);
		
		PageUtils pageUtil = new PageUtils(userList, total, query.getLimit(), query.getPage());
		
		return R.ok().put("page", pageUtil);
	}
	
	/**
	 * 获取登录的用户信息
	 */
	@RequestMapping("/info")
	public R info(){
		return R.ok().put("user", getUser());
	}

	/**
	 * 获取RSA的公钥
	 * @return
	 */
	@RequestMapping("/rsa/public")
	public R rsa1024PublicKey(){
		try {
			byte[] publicKey = RSA1024Utils.readFileKey("./public.key");
            String publicKeyBase64 = Base64.encodeToString(publicKey);
            return R.ok().put("rsa1024PublicKeyBase64", publicKeyBase64);
		} catch (Exception e) {
			return R.error(ErrorCode.INVALID_RSA_READ_PUBLIC_KEY);
		}
	}

    /**
     * 生成RSA1024公私密钥对
     * @return
     */
	@RequestMapping("/rsa/genPairkey")
	public R genRsa1024PairKey(){
        try {
            KeyPair keyPair = RSA1024Utils.genKeyPair();
            byte[] publicKey = RSA1024Utils.getPublicKey(keyPair);
            byte[] privateKey = RSA1024Utils.getPrivateKey(keyPair);
            log.debug("public : {}" , Base64.encodeToString(publicKey));
            log.debug("private : {}", Base64.encodeToString(privateKey));
            RSA1024Utils.saveFileKey("./public.key", publicKey);
            RSA1024Utils.saveFileKey("./private.key", privateKey);

            return R.ok();
        } catch (Exception e) {
            return R.error(ErrorCode.INVALID_RSA_GEN_PAIRKEY);
        }

    }
	
	/**
	 * 修改登录用户密码
	 */
	@SysLog("修改密码")
	@RequestMapping("/password")
	public R password(String password, String newPassword){
		Assert.isBlank(newPassword, "新密码不为能空");
		
		//sha256加密
		password = new Sha256Hash(password).toHex();
		//sha256加密
		newPassword = new Sha256Hash(newPassword).toHex();
				
		//更新密码
		int count = sysUserService.updatePassword(getUserId(), password, newPassword);
		if(count == 0){
			return R.error("原密码不正确");
		}
		
		//退出
		ShiroUtils.logout();
		
		return R.ok();
	}
	
	/**
	 * 用户信息
	 */
	@RequestMapping("/info/{userId}")
	@RequiresPermissions("sys:user:info")
	public R info(@PathVariable("userId") Long userId){
		SysUserEntity user = sysUserService.queryObject(userId);
		
		//获取用户所属的角色列表
		List<Long> roleIdList = sysUserRoleService.queryRoleIdList(userId);
		user.setRoleIdList(roleIdList);
		
		return R.ok().put("user", user);
	}
	
	/**
	 * 保存用户
	 */
	@SysLog("保存用户")
	@RequestMapping("/save")
	@RequiresPermissions("sys:user:save")
	public R save(@RequestBody SysUserEntity user){
		ValidatorUtils.validateEntity(user, AddGroup.class);
		// 进行解密之后，存储
        try {
            // 私钥获取,解密
            byte[] privateKey = RSA1024Utils.readFileKey("./private.key");
            PrivateKey rsaPrivateKey = RSA1024Utils.byteToPrivateKey(privateKey);
            String encPwdBase64 = user.getPassword();
            byte[] encPwd = Base64.decode(encPwdBase64);
            String pwd = new String(RSA1024Utils.decrypt(encPwd, rsaPrivateKey));
            user.setPassword(pwd);
        } catch (Exception e) {
            return R.error(ErrorCode.INVALID_RSA_READ_PUBLIC_KEY);
        }
		user.setCreateUserId(getUserId());
		sysUserService.save(user);
		
		return R.ok();
	}
	
	/**
	 * 修改用户
	 */
	@SysLog("修改用户")
	@RequestMapping("/update")
	@RequiresPermissions("sys:user:update")
	public R update(@RequestBody SysUserEntity user){
		ValidatorUtils.validateEntity(user, UpdateGroup.class);
		
		user.setCreateUserId(getUserId());
		sysUserService.update(user);
		
		return R.ok();
	}
	
	/**
	 * 删除用户
	 */
	@SysLog("删除用户")
	@RequestMapping("/delete")
	@RequiresPermissions("sys:user:delete")
	public R delete(@RequestBody Long[] userIds){
		if(ArrayUtils.contains(userIds, 1L)){
			return R.error("系统管理员不能删除");
		}
		
		if(ArrayUtils.contains(userIds, getUserId())){
			return R.error("当前用户不能删除");
		}
		
		sysUserService.deleteBatch(userIds);
		
		return R.ok();
	}
}
