webpackJsonp([22],{150:function(t,o,e){"use strict";e.d(o,"a",function(){return f});var n=e(2),i=e.n(n),d=e(1),r=e.n(d),a=e(3),s=e.n(a),c=e(4),u=e.n(c),l=e(0),b=e.n(l),v=e(10),h=e.n(v),f=function(t){function o(){var e,n,i;r()(this,o);for(var d=arguments.length,a=Array(d),c=0;c<d;c++)a[c]=arguments[c];return e=n=s()(this,t.call.apply(t,[this].concat(a))),n.handleClick=function(){n.props.onClick()},i=e,s()(n,i)}return u()(o,t),o.prototype.render=function(){var t=this.props,o=t.icon,e=t.type,n=t.active,d=t.columnHeaderId,r="";return o&&(r=i()("i",{className:"fa fa-fw fa-"+o+" column-header__icon"})),i()("h1",{className:h()("column-header",{active:n}),id:d||null},void 0,i()("button",{onClick:this.handleClick},void 0,r,e))},o}(b.a.PureComponent)},283:function(t,o,e){"use strict";e.d(o,"a",function(){return y});var n=e(2),i=e.n(n),d=e(1),r=e.n(d),a=e(3),s=e.n(a),c=e(4),u=e.n(c),l=e(34),b=e.n(l),v=e(0),h=e.n(v),f=e(150),k=e(90),p=e(35),y=function(t){function o(){var e,n,i;r()(this,o);for(var d=arguments.length,a=Array(d),c=0;c<d;c++)a[c]=arguments[c];return e=n=s()(this,t.call.apply(t,[this].concat(a))),n.handleHeaderClick=function(){var t=n.node.querySelector(".scrollable");t&&(n._interruptScrollAnimation=Object(k.b)(t))},n.handleScroll=b()(function(){void 0!==n._interruptScrollAnimation&&n._interruptScrollAnimation()},200),n.setRef=function(t){n.node=t},i=e,s()(n,i)}return u()(o,t),o.prototype.scrollTop=function(){var t=this.node.querySelector(".scrollable");t&&(this._interruptScrollAnimation=Object(k.b)(t))},o.prototype.render=function(){var t=this.props,o=t.heading,e=t.icon,n=t.children,d=t.active,r=t.hideHeadingOnMobile,a=o&&(!r||r&&!Object(p.b)(window.innerWidth)),s=a&&o.replace(/ /g,"-"),c=a&&i()(f.a,{icon:e,active:d,type:o,onClick:this.handleHeaderClick,columnHeaderId:s});return h.a.createElement("div",{ref:this.setRef,role:"region","aria-labelledby":s,className:"column",onScroll:this.handleScroll},c,n)},o}(h.a.PureComponent)},286:function(t,o,e){"use strict";e.d(o,"a",function(){return y});var n,i,d=e(2),r=e.n(d),a=e(1),s=e.n(a),c=e(3),u=e.n(c),l=e(4),b=e.n(l),v=e(0),h=e.n(v),f=e(6),k=e(5),p=e.n(k),y=(i=n=function(t){function o(){var e,n,i;s()(this,o);for(var d=arguments.length,r=Array(d),a=0;a<d;a++)r[a]=arguments[a];return e=n=u()(this,t.call.apply(t,[this].concat(r))),n.handleClick=function(){window.history&&1===window.history.length?n.context.router.history.push("/"):n.context.router.history.goBack()},i=e,u()(n,i)}return b()(o,t),o.prototype.render=function(){return r()("button",{onClick:this.handleClick,className:"column-back-button"},void 0,r()("i",{className:"fa fa-fw fa-chevron-left column-back-button__icon"}),r()(f.b,{id:"column_back_button.label",defaultMessage:"Back"}))},o}(h.a.PureComponent),n.contextTypes={router:p.a.object},i)},298:function(t,o,e){"use strict";e.d(o,"a",function(){return h});var n=e(2),i=e.n(n),d=e(1),r=e.n(d),a=e(3),s=e.n(a),c=e(4),u=e.n(c),l=e(0),b=(e.n(l),e(6)),v=e(286),h=function(t){function o(){return r()(this,o),s()(this,t.apply(this,arguments))}return u()(o,t),o.prototype.render=function(){return i()("div",{className:"column-back-button--slim"},void 0,i()("div",{role:"button",tabIndex:"0",onClick:this.handleClick,className:"column-back-button column-back-button--slim-button"},void 0,i()("i",{className:"fa fa-fw fa-chevron-left column-back-button__icon"}),i()(b.b,{id:"column_back_button.label",defaultMessage:"Back"})))},o}(v.a)},812:function(t,o,e){"use strict";Object.defineProperty(o,"__esModule",{value:!0}),e.d(o,"default",function(){return C});var n,i,d,r=e(2),a=e.n(r),s=e(1),c=e.n(s),u=e(3),l=e.n(u),b=e(4),v=e.n(b),h=e(0),f=(e.n(h),e(283)),k=e(298),p=e(6),y=e(5),m=e.n(y),g=e(12),_=e.n(g),M=Object(p.f)({heading:{id:"keyboard_shortcuts.heading",defaultMessage:"Keyboard Shortcuts"}}),C=Object(p.g)((d=i=function(t){function o(){return c()(this,o),l()(this,t.apply(this,arguments))}return v()(o,t),o.prototype.render=function(){var t=this.props.intl;return a()(f.a,{icon:"question",heading:t.formatMessage(M.heading)},void 0,a()(k.a,{}),a()("div",{className:"keyboard-shortcuts scrollable optionally-scrollable"},void 0,a()("table",{},void 0,a()("thead",{},void 0,a()("tr",{},void 0,a()("th",{},void 0,a()(p.b,{id:"keyboard_shortcuts.hotkey",defaultMessage:"Hotkey"})),a()("th",{},void 0,a()(p.b,{id:"keyboard_shortcuts.description",defaultMessage:"Description"})))),a()("tbody",{},void 0,a()("tr",{},void 0,a()("td",{},void 0,a()("kbd",{},void 0,"r")),a()("td",{},void 0,a()(p.b,{id:"keyboard_shortcuts.reply",defaultMessage:"to reply"}))),a()("tr",{},void 0,a()("td",{},void 0,a()("kbd",{},void 0,"m")),a()("td",{},void 0,a()(p.b,{id:"keyboard_shortcuts.mention",defaultMessage:"to mention author"}))),a()("tr",{},void 0,a()("td",{},void 0,a()("kbd",{},void 0,"f")),a()("td",{},void 0,a()(p.b,{id:"keyboard_shortcuts.favourite",defaultMessage:"to favourite"}))),a()("tr",{},void 0,a()("td",{},void 0,a()("kbd",{},void 0,"b")),a()("td",{},void 0,a()(p.b,{id:"keyboard_shortcuts.boost",defaultMessage:"to boost"}))),a()("tr",{},void 0,a()("td",{},void 0,a()("kbd",{},void 0,"enter")),a()("td",{},void 0,a()(p.b,{id:"keyboard_shortcuts.enter",defaultMessage:"to open status"}))),a()("tr",{},void 0,a()("td",{},void 0,a()("kbd",{},void 0,"up")),a()("td",{},void 0,a()(p.b,{id:"keyboard_shortcuts.up",defaultMessage:"to move up in the list"}))),a()("tr",{},void 0,a()("td",{},void 0,a()("kbd",{},void 0,"down")),a()("td",{},void 0,a()(p.b,{id:"keyboard_shortcuts.down",defaultMessage:"to move down in the list"}))),a()("tr",{},void 0,a()("td",{},void 0,a()("kbd",{},void 0,"1"),"-",a()("kbd",{},void 0,"9")),a()("td",{},void 0,a()(p.b,{id:"keyboard_shortcuts.column",defaultMessage:"to focus a status in one of the columns"}))),a()("tr",{},void 0,a()("td",{},void 0,a()("kbd",{},void 0,"n")),a()("td",{},void 0,a()(p.b,{id:"keyboard_shortcuts.compose",defaultMessage:"to focus the compose textarea"}))),a()("tr",{},void 0,a()("td",{},void 0,a()("kbd",{},void 0,"alt"),"+",a()("kbd",{},void 0,"n")),a()("td",{},void 0,a()(p.b,{id:"keyboard_shortcuts.toot",defaultMessage:"to start a brand new toot"}))),a()("tr",{},void 0,a()("td",{},void 0,a()("kbd",{},void 0,"backspace")),a()("td",{},void 0,a()(p.b,{id:"keyboard_shortcuts.back",defaultMessage:"to navigate back"}))),a()("tr",{},void 0,a()("td",{},void 0,a()("kbd",{},void 0,"s")),a()("td",{},void 0,a()(p.b,{id:"keyboard_shortcuts.search",defaultMessage:"to focus search"}))),a()("tr",{},void 0,a()("td",{},void 0,a()("kbd",{},void 0,"esc")),a()("td",{},void 0,a()(p.b,{id:"keyboard_shortcuts.unfocus",defaultMessage:"to un-focus compose textarea/search"}))),a()("tr",{},void 0,a()("td",{},void 0,a()("kbd",{},void 0,"?")),a()("td",{},void 0,a()(p.b,{id:"keyboard_shortcuts.legend",defaultMessage:"to display this legend"})))))))},o}(_.a),i.propTypes={intl:m.a.object.isRequired,multiColumn:m.a.bool},n=d))||n}});
//# sourceMappingURL=keyboard_shortcuts.js.map