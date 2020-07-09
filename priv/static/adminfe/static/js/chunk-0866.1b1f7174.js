(window.webpackJsonp=window.webpackJsonp||[]).push([["chunk-0866"],{"13xp":function(s,e,t){"use strict";var r=t("2r4G");t.n(r).a},"2r4G":function(s,e,t){},"4bFr":function(s,e,t){"use strict";t.r(e);var r=t("ot3S"),i=t("tPM3"),a=t("o0o1"),n=t.n(a),o=t("yXPU"),u=t.n(o),l=t("XJYT"),c={name:"SecuritySettingsModal",props:{visible:{type:Boolean,default:!1},user:{type:Object,default:function(){return{}}}},data:function(){return{securitySettingsForm:{newEmail:"",newPassword:"",isEmailLoading:!1,isPasswordLoading:!1}}},computed:{isDesktop:function(){return"desktop"===this.$store.state.app.device},getLabelWidth:function(){return this.isDesktop?"120px":"85px"},userCredentials:function(){return this.$store.state.userProfile.userCredentials}},mounted:function(){var s=u()(n.a.mark(function s(){return n.a.wrap(function(s){for(;;)switch(s.prev=s.next){case 0:return s.next=2,this.$store.dispatch("FetchUserCredentials",{nickname:this.user.nickname});case 2:this.securitySettingsForm.newEmail=this.userCredentials.email;case 3:case"end":return s.stop()}},s,this)}));return function(){return s.apply(this,arguments)}}(),methods:{updateEmail:function(){var s=u()(n.a.mark(function s(){var e;return n.a.wrap(function(s){for(;;)switch(s.prev=s.next){case 0:return e={email:this.securitySettingsForm.newEmail},this.securitySettingsForm.isEmailLoading=!0,s.next=4,this.$store.dispatch("UpdateUserCredentials",{nickname:this.user.nickname,credentials:e});case 4:this.securitySettingsForm.isEmailLoading=!1,Object(l.Message)({message:this.$t("userProfile.securitySettings.emailUpdated"),type:"success",duration:5e3});case 6:case"end":return s.stop()}},s,this)}));return function(){return s.apply(this,arguments)}}(),updatePassword:function(){var s=u()(n.a.mark(function s(){var e;return n.a.wrap(function(s){for(;;)switch(s.prev=s.next){case 0:return e={password:this.securitySettingsForm.newPassword},this.securitySettingsForm.isPasswordLoading=!0,s.next=4,this.$store.dispatch("UpdateUserCredentials",{nickname:this.user.nickname,credentials:e});case 4:this.securitySettingsForm.isPasswordLoading=!1,this.securitySettingsForm.newPassword="",Object(l.Message)({message:this.$t("userProfile.securitySettings.passwordUpdated"),type:"success",duration:5e3});case 7:case"end":return s.stop()}},s,this)}));return function(){return s.apply(this,arguments)}}(),close:function(){this.$emit("close",!0)}}},d=(t("13xp"),t("KHd+")),p=Object(d.a)(c,function(){var s=this,e=s.$createElement,t=s._self._c||e;return t("el-dialog",{staticClass:"security-settings-modal",attrs:{"before-close":s.close,title:s.$t("userProfile.securitySettings.securitySettings"),visible:s.visible}},[t("el-form",{attrs:{model:s.securitySettingsForm,"label-width":s.getLabelWidth}},[t("el-form-item",{attrs:{label:s.$t("userProfile.securitySettings.email")}},[t("el-input",{attrs:{placeholder:s.$t("userProfile.securitySettings.inputNewEmail")},model:{value:s.securitySettingsForm.newEmail,callback:function(e){s.$set(s.securitySettingsForm,"newEmail",e)},expression:"securitySettingsForm.newEmail"}})],1),s._v(" "),t("el-form-item",[t("el-button",{staticClass:"security-settings-submit-button",attrs:{loading:s.securitySettingsForm.isEmailLoading,disabled:!s.securitySettingsForm.newEmail||s.securitySettingsForm.newEmail===s.userCredentials.email,type:"primary"},on:{click:function(e){return s.updateEmail()}}},[s._v("\n        "+s._s(s.$t("userProfile.securitySettings.submit"))+"\n      ")])],1),s._v(" "),t("el-form-item",{staticClass:"password-input",attrs:{label:s.$t("userProfile.securitySettings.password")}},[t("el-input",{attrs:{placeholder:s.$t("userProfile.securitySettings.inputNewPassword")},model:{value:s.securitySettingsForm.newPassword,callback:function(e){s.$set(s.securitySettingsForm,"newPassword",e)},expression:"securitySettingsForm.newPassword"}}),s._v(" "),t("small",{staticClass:"form-text"},[s._v("\n        "+s._s(s.$t("userProfile.securitySettings.passwordLengthNotice",{minLength:8}))+"\n      ")])],1),s._v(" "),t("el-alert",{staticClass:"password-alert",attrs:{closable:!1,type:"warning","show-icon":""}},[t("p",[s._v(s._s(s.$t("userProfile.securitySettings.passwordChangeWarning1")))]),s._v(" "),t("p",[s._v(s._s(s.$t("userProfile.securitySettings.passwordChangeWarning2")))])]),s._v(" "),t("el-form-item",[t("el-button",{staticClass:"security-settings-submit-button",attrs:{loading:s.securitySettingsForm.isPasswordLoading,disabled:s.securitySettingsForm.newPassword.length<8,type:"primary"},on:{click:function(e){return s.updatePassword()}}},[s._v("\n        "+s._s(s.$t("userProfile.securitySettings.submit"))+"\n      ")])],1)],1)],1)},[],!1,null,null,null);p.options.__file="SecuritySettingsModal.vue";var g=p.exports,v=t("rIUS"),_=t("WjBP"),m={name:"UsersShow",components:{ModerationDropdown:i.a,RebootButton:v.a,ResetPasswordDialog:_.a,Status:r.a,SecuritySettingsModal:g},data:function(){return{showPrivate:!1,resetPasswordDialogOpen:!1,securitySettingsModalVisible:!1}},computed:{isDesktop:function(){return"desktop"===this.$store.state.app.device},isMobile:function(){return"mobile"===this.$store.state.app.device},isTablet:function(){return"tablet"===this.$store.state.app.device},loading:function(){return this.$store.state.users.loading},statuses:function(){return this.$store.state.userProfile.statuses},statusesLoading:function(){return this.$store.state.userProfile.statusesLoading},user:function(){return this.$store.state.userProfile.user},userProfileLoading:function(){return this.$store.state.userProfile.userProfileLoading},userCredentials:function(){return this.$store.state.userProfile.userCredentials}},mounted:function(){this.$store.dispatch("NeedReboot"),this.$store.dispatch("GetNodeInfo"),this.$store.dispatch("FetchUserProfile",{userId:this.$route.params.id,godmode:!1})},methods:{closeResetPasswordDialog:function(){this.resetPasswordDialogOpen=!1,this.$store.dispatch("RemovePasswordToken")},humanizeTag:function(s){return{force_nsfw:"Force NSFW",strip_media:"Strip Media",force_unlisted:"Force Unlisted",sandbox:"Sandbox",disable_remote_subscription:"Disable remote subscription",disable_any_subscription:"Disable any subscription"}[s]},onTogglePrivate:function(){this.$store.dispatch("FetchUserProfile",{userId:this.$route.params.id,godmode:this.showPrivate})},openResetPasswordDialog:function(){this.resetPasswordDialogOpen=!0},propertyExists:function(s,e){return s[e]}}},h=(t("9IXO"),Object(d.a)(m,function(){var s=this,e=s.$createElement,t=s._self._c||e;return s.userProfileLoading?s._e():t("main",[s.isDesktop||s.isTablet?t("header",{staticClass:"user-page-header"},[t("div",{staticClass:"avatar-name-container"},[s.propertyExists(s.user,"avatar")?t("el-avatar",{attrs:{src:s.user.avatar,size:"large"}}):s._e(),s._v(" "),s.propertyExists(s.user,"nickname")?t("h1",[s._v(s._s(s.user.nickname))]):t("h1",{staticClass:"invalid"},[s._v("("+s._s(s.$t("users.invalidNickname"))+")")])],1),s._v(" "),t("div",{staticClass:"left-header-container"},[s.propertyExists(s.user,"nickname")?t("moderation-dropdown",{attrs:{user:s.user,page:"userPage"},on:{"open-reset-token-dialog":s.openResetPasswordDialog}}):s._e(),s._v(" "),t("reboot-button")],1)]):s._e(),s._v(" "),s.isMobile?t("div",{staticClass:"user-page-header-container"},[t("header",{staticClass:"user-page-header"},[t("div",{staticClass:"avatar-name-container"},[s.propertyExists(s.user,"avatar")?t("el-avatar",{attrs:{src:s.user.avatar,size:"large"}}):s._e(),s._v(" "),s.propertyExists(s.user,"nickname")?t("h1",[s._v(s._s(s.user.nickname))]):t("h1",{staticClass:"invalid"},[s._v("("+s._s(s.$t("users.invalidNickname"))+")")])],1),s._v(" "),t("reboot-button")],1),s._v(" "),s.propertyExists(s.user,"nickname")?t("moderation-dropdown",{attrs:{user:s.user,page:"userPage"},on:{"open-reset-token-dialog":s.openResetPasswordDialog}}):s._e()],1):s._e(),s._v(" "),t("reset-password-dialog",{attrs:{"reset-password-dialog-open":s.resetPasswordDialogOpen},on:{"close-reset-token-dialog":s.closeResetPasswordDialog}}),s._v(" "),t("div",{staticClass:"user-profile-container"},[t("el-card",{staticClass:"user-profile-card"},[t("div",{staticClass:"el-table el-table--fit el-table--enable-row-hover el-table--enable-row-transition el-table--medium"},[s.propertyExists(s.user,"nickname")?s._e():t("el-tag",{staticClass:"invalid-user-tag",attrs:{type:"info"}},[s._v("\n          "+s._s(s.$t("users.invalidAccount"))+"\n        ")]),s._v(" "),t("table",{staticClass:"user-profile-table"},[t("tbody",[t("tr",{staticClass:"el-table__row"},[t("td",{staticClass:"name-col"},[s._v("ID")]),s._v(" "),t("td",{staticClass:"value-col"},[s._v("\n                "+s._s(s.user.id)+"\n              ")])]),s._v(" "),t("tr",{staticClass:"el-table__row"},[t("td",[s._v(s._s(s.$t("userProfile.tags")))]),s._v(" "),t("td",[0!==s.user.tags.length&&s.propertyExists(s.user,"tags")?s._l(s.user.tags,function(e){return t("el-tag",{key:e,staticClass:"user-profile-tag"},[s._v(s._s(s.humanizeTag(e)))])}):t("span",[s._v("—")])],2)]),s._v(" "),t("tr",{staticClass:"el-table__row"},[t("td",[s._v(s._s(s.$t("userProfile.roles")))]),s._v(" "),t("td",[s.user.roles.admin?t("el-tag",{staticClass:"user-profile-tag"},[s._v("\n                  "+s._s(s.$t("users.admin"))+"\n                ")]):s._e(),s._v(" "),s.user.roles.moderator?t("el-tag",{staticClass:"user-profile-tag"},[s._v("\n                  "+s._s(s.$t("users.moderator"))+"\n                ")]):s._e(),s._v(" "),s.propertyExists(s.user,"roles")&&(s.user.roles.moderator||s.user.roles.admin)?s._e():t("span",[s._v("—")])],1)]),s._v(" "),t("tr",{staticClass:"el-table__row"},[t("td",[s._v(s._s(s.$t("userProfile.accountType")))]),s._v(" "),t("td",[s.user.local?t("el-tag",{attrs:{type:"info"}},[s._v(s._s(s.$t("userProfile.local")))]):s._e(),s._v(" "),s.user.local?s._e():t("el-tag",{attrs:{type:"info"}},[s._v(s._s(s.$t("userProfile.external")))])],1)]),s._v(" "),t("tr",{staticClass:"el-table__row"},[t("td",[s._v(s._s(s.$t("userProfile.status")))]),s._v(" "),t("td",[s.user.deactivated?s._e():t("el-tag",{attrs:{type:"success"}},[s._v(s._s(s.$t("userProfile.active")))]),s._v(" "),s.user.deactivated?t("el-tag",{attrs:{type:"danger"}},[s._v(s._s(s.$t("userProfile.deactivated")))]):s._e()],1)])])])],1),s._v(" "),s.propertyExists(s.user,"nickname")?t("el-button",{staticClass:"security-setting-button",attrs:{icon:"el-icon-lock"},on:{click:function(e){s.securitySettingsModalVisible=!0}}},[s._v("\n        "+s._s(s.$t("userProfile.securitySettings.securitySettings"))+"\n      ")]):s._e(),s._v(" "),s.propertyExists(s.user,"nickname")?t("SecuritySettingsModal",{attrs:{user:s.user,visible:s.securitySettingsModalVisible},on:{close:function(e){s.securitySettingsModalVisible=!1}}}):s._e()],1),s._v(" "),t("div",{staticClass:"recent-statuses-container"},[t("h2",{staticClass:"recent-statuses"},[s._v(s._s(s.$t("userProfile.recentStatuses")))]),s._v(" "),t("el-checkbox",{staticClass:"show-private-statuses",on:{change:s.onTogglePrivate},model:{value:s.showPrivate,callback:function(e){s.showPrivate=e},expression:"showPrivate"}},[s._v("\n        "+s._s(s.$t("statuses.showPrivateStatuses"))+"\n      ")]),s._v(" "),s.statusesLoading?s._e():t("el-timeline",{staticClass:"statuses"},[s._l(s.statuses,function(e){return t("el-timeline-item",{key:e.id},[t("status",{attrs:{status:e,account:e.account,"show-checkbox":!1,"user-id":s.user.id,godmode:s.showPrivate}})],1)}),s._v(" "),0===s.statuses.length?t("p",{staticClass:"no-statuses"},[s._v(s._s(s.$t("userProfile.noStatuses")))]):s._e()],2)],1)],1)],1)},[],!1,null,null,null));h.options.__file="show.vue";e.default=h.exports},"53Av":function(s,e,t){"use strict";var r=t("lOBV");t.n(r).a},"9IXO":function(s,e,t){"use strict";var r=t("msq4");t.n(r).a},RnhZ:function(s,e,t){var r={"./af":"K/tc","./af.js":"K/tc","./ar":"jnO4","./ar-dz":"o1bE","./ar-dz.js":"o1bE","./ar-kw":"Qj4J","./ar-kw.js":"Qj4J","./ar-ly":"HP3h","./ar-ly.js":"HP3h","./ar-ma":"CoRJ","./ar-ma.js":"CoRJ","./ar-sa":"gjCT","./ar-sa.js":"gjCT","./ar-tn":"bYM6","./ar-tn.js":"bYM6","./ar.js":"jnO4","./az":"SFxW","./az.js":"SFxW","./be":"H8ED","./be.js":"H8ED","./bg":"hKrs","./bg.js":"hKrs","./bm":"p/rL","./bm.js":"p/rL","./bn":"kEOa","./bn.js":"kEOa","./bo":"0mo+","./bo.js":"0mo+","./br":"aIdf","./br.js":"aIdf","./bs":"JVSJ","./bs.js":"JVSJ","./ca":"1xZ4","./ca.js":"1xZ4","./cs":"PA2r","./cs.js":"PA2r","./cv":"A+xa","./cv.js":"A+xa","./cy":"l5ep","./cy.js":"l5ep","./da":"DxQv","./da.js":"DxQv","./de":"tGlX","./de-at":"s+uk","./de-at.js":"s+uk","./de-ch":"u3GI","./de-ch.js":"u3GI","./de.js":"tGlX","./dv":"WYrj","./dv.js":"WYrj","./el":"jUeY","./el.js":"jUeY","./en-SG":"zavE","./en-SG.js":"zavE","./en-au":"Dmvi","./en-au.js":"Dmvi","./en-ca":"OIYi","./en-ca.js":"OIYi","./en-gb":"Oaa7","./en-gb.js":"Oaa7","./en-ie":"4dOw","./en-ie.js":"4dOw","./en-il":"czMo","./en-il.js":"czMo","./en-nz":"b1Dy","./en-nz.js":"b1Dy","./eo":"Zduo","./eo.js":"Zduo","./es":"iYuL","./es-do":"CjzT","./es-do.js":"CjzT","./es-us":"Vclq","./es-us.js":"Vclq","./es.js":"iYuL","./et":"7BjC","./et.js":"7BjC","./eu":"D/JM","./eu.js":"D/JM","./fa":"jfSC","./fa.js":"jfSC","./fi":"gekB","./fi.js":"gekB","./fo":"ByF4","./fo.js":"ByF4","./fr":"nyYc","./fr-ca":"2fjn","./fr-ca.js":"2fjn","./fr-ch":"Dkky","./fr-ch.js":"Dkky","./fr.js":"nyYc","./fy":"cRix","./fy.js":"cRix","./ga":"USCx","./ga.js":"USCx","./gd":"9rRi","./gd.js":"9rRi","./gl":"iEDd","./gl.js":"iEDd","./gom-latn":"DKr+","./gom-latn.js":"DKr+","./gu":"4MV3","./gu.js":"4MV3","./he":"x6pH","./he.js":"x6pH","./hi":"3E1r","./hi.js":"3E1r","./hr":"S6ln","./hr.js":"S6ln","./hu":"WxRl","./hu.js":"WxRl","./hy-am":"1rYy","./hy-am.js":"1rYy","./id":"UDhR","./id.js":"UDhR","./is":"BVg3","./is.js":"BVg3","./it":"bpih","./it-ch":"bxKX","./it-ch.js":"bxKX","./it.js":"bpih","./ja":"B55N","./ja.js":"B55N","./jv":"tUCv","./jv.js":"tUCv","./ka":"IBtZ","./ka.js":"IBtZ","./kk":"bXm7","./kk.js":"bXm7","./km":"6B0Y","./km.js":"6B0Y","./kn":"PpIw","./kn.js":"PpIw","./ko":"Ivi+","./ko.js":"Ivi+","./ku":"JCF/","./ku.js":"JCF/","./ky":"lgnt","./ky.js":"lgnt","./lb":"RAwQ","./lb.js":"RAwQ","./lo":"sp3z","./lo.js":"sp3z","./lt":"JvlW","./lt.js":"JvlW","./lv":"uXwI","./lv.js":"uXwI","./me":"KTz0","./me.js":"KTz0","./mi":"aIsn","./mi.js":"aIsn","./mk":"aQkU","./mk.js":"aQkU","./ml":"AvvY","./ml.js":"AvvY","./mn":"lYtQ","./mn.js":"lYtQ","./mr":"Ob0Z","./mr.js":"Ob0Z","./ms":"6+QB","./ms-my":"ZAMP","./ms-my.js":"ZAMP","./ms.js":"6+QB","./mt":"G0Uy","./mt.js":"G0Uy","./my":"honF","./my.js":"honF","./nb":"bOMt","./nb.js":"bOMt","./ne":"OjkT","./ne.js":"OjkT","./nl":"+s0g","./nl-be":"2ykv","./nl-be.js":"2ykv","./nl.js":"+s0g","./nn":"uEye","./nn.js":"uEye","./pa-in":"8/+R","./pa-in.js":"8/+R","./pl":"jVdC","./pl.js":"jVdC","./pt":"8mBD","./pt-br":"0tRk","./pt-br.js":"0tRk","./pt.js":"8mBD","./ro":"lyxo","./ro.js":"lyxo","./ru":"lXzo","./ru.js":"lXzo","./sd":"Z4QM","./sd.js":"Z4QM","./se":"//9w","./se.js":"//9w","./si":"7aV9","./si.js":"7aV9","./sk":"e+ae","./sk.js":"e+ae","./sl":"gVVK","./sl.js":"gVVK","./sq":"yPMs","./sq.js":"yPMs","./sr":"zx6S","./sr-cyrl":"E+lV","./sr-cyrl.js":"E+lV","./sr.js":"zx6S","./ss":"Ur1D","./ss.js":"Ur1D","./sv":"X709","./sv.js":"X709","./sw":"dNwA","./sw.js":"dNwA","./ta":"PeUW","./ta.js":"PeUW","./te":"XLvN","./te.js":"XLvN","./tet":"V2x9","./tet.js":"V2x9","./tg":"Oxv6","./tg.js":"Oxv6","./th":"EOgW","./th.js":"EOgW","./tl-ph":"Dzi0","./tl-ph.js":"Dzi0","./tlh":"z3Vd","./tlh.js":"z3Vd","./tr":"DoHr","./tr.js":"DoHr","./tzl":"z1FC","./tzl.js":"z1FC","./tzm":"wQk9","./tzm-latn":"tT3J","./tzm-latn.js":"tT3J","./tzm.js":"wQk9","./ug-cn":"YRex","./ug-cn.js":"YRex","./uk":"raLr","./uk.js":"raLr","./ur":"UpQW","./ur.js":"UpQW","./uz":"Loxo","./uz-latn":"AQ68","./uz-latn.js":"AQ68","./uz.js":"Loxo","./vi":"KSF8","./vi.js":"KSF8","./x-pseudo":"/X5v","./x-pseudo.js":"/X5v","./yo":"fzPg","./yo.js":"fzPg","./zh-cn":"XDpg","./zh-cn.js":"XDpg","./zh-hk":"SatO","./zh-hk.js":"SatO","./zh-tw":"kOpN","./zh-tw.js":"kOpN"};function i(s){var e=a(s);return t(e)}function a(s){if(!t.o(r,s)){var e=new Error("Cannot find module '"+s+"'");throw e.code="MODULE_NOT_FOUND",e}return r[s]}i.keys=function(){return Object.keys(r)},i.resolve=a,s.exports=i,i.id="RnhZ"},WjBP:function(s,e,t){"use strict";var r={name:"ResetPasswordDialog",props:{resetPasswordDialogOpen:{type:Boolean,default:!1}},computed:{dialogOpen:function(){return this.resetPasswordDialogOpen},loading:function(){return this.$store.state.users.loading},passwordResetLink:function(){return this.$store.state.users.passwordResetToken.link},passwordResetToken:function(){return this.$store.state.users.passwordResetToken.token}},methods:{closeResetPasswordDialog:function(){this.$emit("close-reset-token-dialog")}}},i=t("KHd+"),a=Object(i.a)(r,function(){var s=this,e=s.$createElement,t=s._self._c||e;return t("el-dialog",{directives:[{name:"loading",rawName:"v-loading",value:s.loading,expression:"loading"}],attrs:{visible:s.dialogOpen,title:s.$t("users.passwordResetTokenCreated"),"custom-class":"password-reset-token-dialog"},on:{close:s.closeResetPasswordDialog}},[t("div",[t("p",{staticClass:"password-reset-token"},[s._v(s._s(s.$t("users.passwordResetTokenGenerated"))+" "+s._s(s.passwordResetToken))]),s._v(" "),t("p",[s._v(s._s(s.$t("users.linkToResetPassword"))+"\n      "),t("a",{staticClass:"reset-password-link",attrs:{href:s.passwordResetLink,target:"_blank"}},[s._v(s._s(s.passwordResetLink))])])])])},[],!1,null,null,null);a.options.__file="ResetPasswordDialog.vue";e.a=a.exports},lOBV:function(s,e,t){},msq4:function(s,e,t){},tPM3:function(s,e,t){"use strict";var r={name:"ModerationDropdown",props:{user:{type:Object,default:function(){return{}}},page:{type:String,default:"users"},statusId:{type:String,default:""}},computed:{isDesktop:function(){return"desktop"===this.$store.state.app.device}},methods:{getPasswordResetToken:function(s){this.$emit("open-reset-token-dialog"),this.$store.dispatch("GetPasswordResetToken",s)},handleConfirmationResend:function(s){this.$store.dispatch("ResendConfirmationEmail",[s])},handleDeletion:function(s){this.$store.dispatch("DeleteUsers",{users:[s],_userId:s.id})},handleEmailConfirmation:function(s){this.$store.dispatch("ConfirmUsersEmail",{users:[s],_userId:s.id,_statusId:this.statusId})},requirePasswordReset:function(s){this.$store.state.user.nodeInfo.metadata.mailerEnabled?this.$store.dispatch("RequirePasswordReset",[s]):this.$alert(this.$t("users.mailerMustBeEnabled"),"Error",{type:"error"})},showAdminAction:function(s){var e=s.local,t=s.id;return e&&this.showDeactivatedButton(t)},showDeactivatedButton:function(s){return this.$store.state.user.id!==s},toggleActivation:function(s){s.deactivated?this.$store.dispatch("ActivateUsers",{users:[s],_userId:s.id}):this.$store.dispatch("DeactivateUsers",{users:[s],_userId:s.id})},toggleTag:function(s,e){s.tags.includes(e)?this.$store.dispatch("RemoveTag",{users:[s],tag:e,_userId:s.id,_statusId:this.statusId}):this.$store.dispatch("AddTag",{users:[s],tag:e,_userId:s.id,_statusId:this.statusId})},toggleUserRight:function(s,e){s.roles[e]?this.$store.dispatch("DeleteRight",{users:[s],right:e,_userId:s.id,_statusId:this.statusId}):this.$store.dispatch("AddRight",{users:[s],right:e,_userId:s.id,_statusId:this.statusId})}}},i=(t("53Av"),t("KHd+")),a=Object(i.a)(r,function(){var s=this,e=s.$createElement,t=s._self._c||e;return t("el-dropdown",{attrs:{"hide-on-click":!1,size:"small",trigger:"click",placement:"top-start"},nativeOn:{click:function(s){s.stopPropagation()}}},[t("div",["users"===s.page?t("el-button",{staticClass:"el-dropdown-link",attrs:{type:"text"}},[s._v("\n      "+s._s(s.$t("users.moderation"))+"\n      "),s.isDesktop?t("i",{staticClass:"el-icon-arrow-down el-icon--right"}):s._e()]):s._e(),s._v(" "),"userPage"===s.page||"statusPage"===s.page?t("el-button",{staticClass:"moderate-user-button"},[t("span",{staticClass:"moderate-user-button-container"},[t("span",[t("i",{staticClass:"el-icon-edit"}),s._v("\n          "+s._s(s.$t("users.moderateUser"))+"\n        ")]),s._v(" "),t("i",{staticClass:"el-icon-arrow-down el-icon--right"})])]):s._e()],1),s._v(" "),t("el-dropdown-menu",{attrs:{slot:"dropdown"},slot:"dropdown"},[s.showAdminAction(s.user)?t("el-dropdown-item",{nativeOn:{click:function(e){return s.toggleUserRight(s.user,"admin")}}},[s._v("\n      "+s._s(s.user.roles.admin?s.$t("users.revokeAdmin"):s.$t("users.grantAdmin"))+"\n    ")]):s._e(),s._v(" "),s.showAdminAction(s.user)?t("el-dropdown-item",{nativeOn:{click:function(e){return s.toggleUserRight(s.user,"moderator")}}},[s._v("\n      "+s._s(s.user.roles.moderator?s.$t("users.revokeModerator"):s.$t("users.grantModerator"))+"\n    ")]):s._e(),s._v(" "),s.showDeactivatedButton(s.user.id)&&"statusPage"!==s.page?t("el-dropdown-item",{attrs:{divided:s.showAdminAction(s.user)},nativeOn:{click:function(e){return s.toggleActivation(s.user)}}},[s._v("\n      "+s._s(s.user.deactivated?s.$t("users.activateAccount"):s.$t("users.deactivateAccount"))+"\n    ")]):s._e(),s._v(" "),s.showDeactivatedButton(s.user.id)&&"statusPage"!==s.page?t("el-dropdown-item",{nativeOn:{click:function(e){return s.handleDeletion(s.user)}}},[s._v("\n      "+s._s(s.$t("users.deleteAccount"))+"\n    ")]):s._e(),s._v(" "),s.user.local&&s.user.confirmation_pending?t("el-dropdown-item",{attrs:{divided:""},nativeOn:{click:function(e){return s.handleEmailConfirmation(s.user)}}},[s._v("\n      "+s._s(s.$t("users.confirmAccount"))+"\n    ")]):s._e(),s._v(" "),s.user.local&&s.user.confirmation_pending?t("el-dropdown-item",{nativeOn:{click:function(e){return s.handleConfirmationResend(s.user)}}},[s._v("\n      "+s._s(s.$t("users.resendConfirmation"))+"\n    ")]):s._e(),s._v(" "),t("el-dropdown-item",{class:{"active-tag":s.user.tags.includes("force_nsfw")},attrs:{divided:s.showAdminAction(s.user)},nativeOn:{click:function(e){return s.toggleTag(s.user,"force_nsfw")}}},[s._v("\n      "+s._s(s.$t("users.forceNsfw"))+"\n      "),s.user.tags.includes("force_nsfw")?t("i",{staticClass:"el-icon-check"}):s._e()]),s._v(" "),t("el-dropdown-item",{class:{"active-tag":s.user.tags.includes("strip_media")},nativeOn:{click:function(e){return s.toggleTag(s.user,"strip_media")}}},[s._v("\n      "+s._s(s.$t("users.stripMedia"))+"\n      "),s.user.tags.includes("strip_media")?t("i",{staticClass:"el-icon-check"}):s._e()]),s._v(" "),t("el-dropdown-item",{class:{"active-tag":s.user.tags.includes("force_unlisted")},nativeOn:{click:function(e){return s.toggleTag(s.user,"force_unlisted")}}},[s._v("\n      "+s._s(s.$t("users.forceUnlisted"))+"\n      "),s.user.tags.includes("force_unlisted")?t("i",{staticClass:"el-icon-check"}):s._e()]),s._v(" "),t("el-dropdown-item",{class:{"active-tag":s.user.tags.includes("sandbox")},nativeOn:{click:function(e){return s.toggleTag(s.user,"sandbox")}}},[s._v("\n      "+s._s(s.$t("users.sandbox"))+"\n      "),s.user.tags.includes("sandbox")?t("i",{staticClass:"el-icon-check"}):s._e()]),s._v(" "),s.user.local?t("el-dropdown-item",{class:{"active-tag":s.user.tags.includes("disable_remote_subscription")},nativeOn:{click:function(e){return s.toggleTag(s.user,"disable_remote_subscription")}}},[s._v("\n      "+s._s(s.$t("users.disableRemoteSubscription"))+"\n      "),s.user.tags.includes("disable_remote_subscription")?t("i",{staticClass:"el-icon-check"}):s._e()]):s._e(),s._v(" "),s.user.local?t("el-dropdown-item",{class:{"active-tag":s.user.tags.includes("disable_any_subscription")},nativeOn:{click:function(e){return s.toggleTag(s.user,"disable_any_subscription")}}},[s._v("\n      "+s._s(s.$t("users.disableAnySubscription"))+"\n      "),s.user.tags.includes("disable_any_subscription")?t("i",{staticClass:"el-icon-check"}):s._e()]):s._e(),s._v(" "),s.user.local?t("el-dropdown-item",{attrs:{divided:""},nativeOn:{click:function(e){return s.getPasswordResetToken(s.user.nickname)}}},[s._v("\n      "+s._s(s.$t("users.getPasswordResetToken"))+"\n    ")]):s._e(),s._v(" "),s.user.local?t("el-dropdown-item",{nativeOn:{click:function(e){return s.requirePasswordReset(s.user)}}},[s._v("\n      "+s._s(s.$t("users.requirePasswordReset"))+"\n    ")]):s._e()],1)],1)},[],!1,null,null,null);a.options.__file="ModerationDropdown.vue";e.a=a.exports}}]);
//# sourceMappingURL=chunk-0866.1b1f7174.js.map