!function(r,t){"object"==typeof exports&&"undefined"!=typeof module?t(exports):"function"==typeof define&&define.amd?define(["exports"],t):t((r="undefined"!=typeof globalThis?globalThis:r||self).$3={})}(this,(function(r){"use strict";var t="undefined"!=typeof globalThis?globalThis:"undefined"!=typeof window?window:"undefined"!=typeof global?global:"undefined"!=typeof self?self:{};function e(r){return r&&r.__esModule&&Object.prototype.hasOwnProperty.call(r,"default")?r.default:r}function n(r){if(r.__esModule)return r;var t=r.default;if("function"==typeof t){var e=function r(){return this instanceof r?Reflect.construct(t,arguments,this.constructor):t.apply(this,arguments)};e.prototype=t.prototype}else e={};return Object.defineProperty(e,"__esModule",{value:!0}),Object.keys(r).forEach((function(t){var n=Object.getOwnPropertyDescriptor(r,t);Object.defineProperty(e,t,n.get?n:{enumerable:!0,get:function(){return r[t]}})})),e}function o(r){throw new Error('Could not dynamically require "'+r+'". Please configure the dynamicRequireTargets or/and ignoreDynamicRequires option of @rollup/plugin-commonjs appropriately for this require call to work.')}var i={exports:{}},a=n(Object.freeze({__proto__:null,default:{}}));!function(r){!function(r){var t=function(r){var t,e=new Float64Array(16);if(r)for(t=0;t<r.length;t++)e[t]=r[t];return e},e=function(){throw new Error("no PRNG")},n=new Uint8Array(16),i=new Uint8Array(32);i[0]=9;var s=t(),h=t([1]),f=t([56129,1]),c=t([30883,4953,19914,30187,55467,16705,2637,112,59544,30585,16505,36039,65139,11119,27886,20995]),u=t([61785,9906,39828,60374,45398,33411,5274,224,53552,61171,33010,6542,64743,22239,55772,9222]),y=t([54554,36645,11616,51542,42930,38181,51040,26924,56412,64982,57905,49316,21502,52590,14035,8553]),l=t([26200,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214]),p=t([41136,18958,6951,50414,58488,44335,6150,12099,55207,15867,153,11085,57099,20417,9344,11139]);function d(r,t,e,n){r[t]=e>>24&255,r[t+1]=e>>16&255,r[t+2]=e>>8&255,r[t+3]=255&e,r[t+4]=n>>24&255,r[t+5]=n>>16&255,r[t+6]=n>>8&255,r[t+7]=255&n}function w(r,t,e,n,o){var i,a=0;for(i=0;i<o;i++)a|=r[t+i]^e[n+i];return(1&a-1>>>8)-1}function b(r,t,e,n){return w(r,t,e,n,16)}function g(r,t,e,n){return w(r,t,e,n,32)}function v(r,t,e,n){!function(r,t,e,n){for(var o,i=255&n[0]|(255&n[1])<<8|(255&n[2])<<16|(255&n[3])<<24,a=255&e[0]|(255&e[1])<<8|(255&e[2])<<16|(255&e[3])<<24,s=255&e[4]|(255&e[5])<<8|(255&e[6])<<16|(255&e[7])<<24,h=255&e[8]|(255&e[9])<<8|(255&e[10])<<16|(255&e[11])<<24,f=255&e[12]|(255&e[13])<<8|(255&e[14])<<16|(255&e[15])<<24,c=255&n[4]|(255&n[5])<<8|(255&n[6])<<16|(255&n[7])<<24,u=255&t[0]|(255&t[1])<<8|(255&t[2])<<16|(255&t[3])<<24,y=255&t[4]|(255&t[5])<<8|(255&t[6])<<16|(255&t[7])<<24,l=255&t[8]|(255&t[9])<<8|(255&t[10])<<16|(255&t[11])<<24,p=255&t[12]|(255&t[13])<<8|(255&t[14])<<16|(255&t[15])<<24,d=255&n[8]|(255&n[9])<<8|(255&n[10])<<16|(255&n[11])<<24,w=255&e[16]|(255&e[17])<<8|(255&e[18])<<16|(255&e[19])<<24,b=255&e[20]|(255&e[21])<<8|(255&e[22])<<16|(255&e[23])<<24,g=255&e[24]|(255&e[25])<<8|(255&e[26])<<16|(255&e[27])<<24,v=255&e[28]|(255&e[29])<<8|(255&e[30])<<16|(255&e[31])<<24,A=255&n[12]|(255&n[13])<<8|(255&n[14])<<16|(255&n[15])<<24,_=i,x=a,U=s,m=h,E=f,M=c,K=u,B=y,S=l,T=p,k=d,P=w,L=b,Y=g,z=v,O=A,R=0;R<20;R+=2)_^=(o=(L^=(o=(S^=(o=(E^=(o=_+L|0)<<7|o>>>25)+_|0)<<9|o>>>23)+E|0)<<13|o>>>19)+S|0)<<18|o>>>14,M^=(o=(x^=(o=(Y^=(o=(T^=(o=M+x|0)<<7|o>>>25)+M|0)<<9|o>>>23)+T|0)<<13|o>>>19)+Y|0)<<18|o>>>14,k^=(o=(K^=(o=(U^=(o=(z^=(o=k+K|0)<<7|o>>>25)+k|0)<<9|o>>>23)+z|0)<<13|o>>>19)+U|0)<<18|o>>>14,O^=(o=(P^=(o=(B^=(o=(m^=(o=O+P|0)<<7|o>>>25)+O|0)<<9|o>>>23)+m|0)<<13|o>>>19)+B|0)<<18|o>>>14,_^=(o=(m^=(o=(U^=(o=(x^=(o=_+m|0)<<7|o>>>25)+_|0)<<9|o>>>23)+x|0)<<13|o>>>19)+U|0)<<18|o>>>14,M^=(o=(E^=(o=(B^=(o=(K^=(o=M+E|0)<<7|o>>>25)+M|0)<<9|o>>>23)+K|0)<<13|o>>>19)+B|0)<<18|o>>>14,k^=(o=(T^=(o=(S^=(o=(P^=(o=k+T|0)<<7|o>>>25)+k|0)<<9|o>>>23)+P|0)<<13|o>>>19)+S|0)<<18|o>>>14,O^=(o=(z^=(o=(Y^=(o=(L^=(o=O+z|0)<<7|o>>>25)+O|0)<<9|o>>>23)+L|0)<<13|o>>>19)+Y|0)<<18|o>>>14;_=_+i|0,x=x+a|0,U=U+s|0,m=m+h|0,E=E+f|0,M=M+c|0,K=K+u|0,B=B+y|0,S=S+l|0,T=T+p|0,k=k+d|0,P=P+w|0,L=L+b|0,Y=Y+g|0,z=z+v|0,O=O+A|0,r[0]=_>>>0&255,r[1]=_>>>8&255,r[2]=_>>>16&255,r[3]=_>>>24&255,r[4]=x>>>0&255,r[5]=x>>>8&255,r[6]=x>>>16&255,r[7]=x>>>24&255,r[8]=U>>>0&255,r[9]=U>>>8&255,r[10]=U>>>16&255,r[11]=U>>>24&255,r[12]=m>>>0&255,r[13]=m>>>8&255,r[14]=m>>>16&255,r[15]=m>>>24&255,r[16]=E>>>0&255,r[17]=E>>>8&255,r[18]=E>>>16&255,r[19]=E>>>24&255,r[20]=M>>>0&255,r[21]=M>>>8&255,r[22]=M>>>16&255,r[23]=M>>>24&255,r[24]=K>>>0&255,r[25]=K>>>8&255,r[26]=K>>>16&255,r[27]=K>>>24&255,r[28]=B>>>0&255,r[29]=B>>>8&255,r[30]=B>>>16&255,r[31]=B>>>24&255,r[32]=S>>>0&255,r[33]=S>>>8&255,r[34]=S>>>16&255,r[35]=S>>>24&255,r[36]=T>>>0&255,r[37]=T>>>8&255,r[38]=T>>>16&255,r[39]=T>>>24&255,r[40]=k>>>0&255,r[41]=k>>>8&255,r[42]=k>>>16&255,r[43]=k>>>24&255,r[44]=P>>>0&255,r[45]=P>>>8&255,r[46]=P>>>16&255,r[47]=P>>>24&255,r[48]=L>>>0&255,r[49]=L>>>8&255,r[50]=L>>>16&255,r[51]=L>>>24&255,r[52]=Y>>>0&255,r[53]=Y>>>8&255,r[54]=Y>>>16&255,r[55]=Y>>>24&255,r[56]=z>>>0&255,r[57]=z>>>8&255,r[58]=z>>>16&255,r[59]=z>>>24&255,r[60]=O>>>0&255,r[61]=O>>>8&255,r[62]=O>>>16&255,r[63]=O>>>24&255}(r,t,e,n)}function A(r,t,e,n){!function(r,t,e,n){for(var o,i=255&n[0]|(255&n[1])<<8|(255&n[2])<<16|(255&n[3])<<24,a=255&e[0]|(255&e[1])<<8|(255&e[2])<<16|(255&e[3])<<24,s=255&e[4]|(255&e[5])<<8|(255&e[6])<<16|(255&e[7])<<24,h=255&e[8]|(255&e[9])<<8|(255&e[10])<<16|(255&e[11])<<24,f=255&e[12]|(255&e[13])<<8|(255&e[14])<<16|(255&e[15])<<24,c=255&n[4]|(255&n[5])<<8|(255&n[6])<<16|(255&n[7])<<24,u=255&t[0]|(255&t[1])<<8|(255&t[2])<<16|(255&t[3])<<24,y=255&t[4]|(255&t[5])<<8|(255&t[6])<<16|(255&t[7])<<24,l=255&t[8]|(255&t[9])<<8|(255&t[10])<<16|(255&t[11])<<24,p=255&t[12]|(255&t[13])<<8|(255&t[14])<<16|(255&t[15])<<24,d=255&n[8]|(255&n[9])<<8|(255&n[10])<<16|(255&n[11])<<24,w=255&e[16]|(255&e[17])<<8|(255&e[18])<<16|(255&e[19])<<24,b=255&e[20]|(255&e[21])<<8|(255&e[22])<<16|(255&e[23])<<24,g=255&e[24]|(255&e[25])<<8|(255&e[26])<<16|(255&e[27])<<24,v=255&e[28]|(255&e[29])<<8|(255&e[30])<<16|(255&e[31])<<24,A=255&n[12]|(255&n[13])<<8|(255&n[14])<<16|(255&n[15])<<24,_=0;_<20;_+=2)i^=(o=(b^=(o=(l^=(o=(f^=(o=i+b|0)<<7|o>>>25)+i|0)<<9|o>>>23)+f|0)<<13|o>>>19)+l|0)<<18|o>>>14,c^=(o=(a^=(o=(g^=(o=(p^=(o=c+a|0)<<7|o>>>25)+c|0)<<9|o>>>23)+p|0)<<13|o>>>19)+g|0)<<18|o>>>14,d^=(o=(u^=(o=(s^=(o=(v^=(o=d+u|0)<<7|o>>>25)+d|0)<<9|o>>>23)+v|0)<<13|o>>>19)+s|0)<<18|o>>>14,A^=(o=(w^=(o=(y^=(o=(h^=(o=A+w|0)<<7|o>>>25)+A|0)<<9|o>>>23)+h|0)<<13|o>>>19)+y|0)<<18|o>>>14,i^=(o=(h^=(o=(s^=(o=(a^=(o=i+h|0)<<7|o>>>25)+i|0)<<9|o>>>23)+a|0)<<13|o>>>19)+s|0)<<18|o>>>14,c^=(o=(f^=(o=(y^=(o=(u^=(o=c+f|0)<<7|o>>>25)+c|0)<<9|o>>>23)+u|0)<<13|o>>>19)+y|0)<<18|o>>>14,d^=(o=(p^=(o=(l^=(o=(w^=(o=d+p|0)<<7|o>>>25)+d|0)<<9|o>>>23)+w|0)<<13|o>>>19)+l|0)<<18|o>>>14,A^=(o=(v^=(o=(g^=(o=(b^=(o=A+v|0)<<7|o>>>25)+A|0)<<9|o>>>23)+b|0)<<13|o>>>19)+g|0)<<18|o>>>14;r[0]=i>>>0&255,r[1]=i>>>8&255,r[2]=i>>>16&255,r[3]=i>>>24&255,r[4]=c>>>0&255,r[5]=c>>>8&255,r[6]=c>>>16&255,r[7]=c>>>24&255,r[8]=d>>>0&255,r[9]=d>>>8&255,r[10]=d>>>16&255,r[11]=d>>>24&255,r[12]=A>>>0&255,r[13]=A>>>8&255,r[14]=A>>>16&255,r[15]=A>>>24&255,r[16]=u>>>0&255,r[17]=u>>>8&255,r[18]=u>>>16&255,r[19]=u>>>24&255,r[20]=y>>>0&255,r[21]=y>>>8&255,r[22]=y>>>16&255,r[23]=y>>>24&255,r[24]=l>>>0&255,r[25]=l>>>8&255,r[26]=l>>>16&255,r[27]=l>>>24&255,r[28]=p>>>0&255,r[29]=p>>>8&255,r[30]=p>>>16&255,r[31]=p>>>24&255}(r,t,e,n)}var _=new Uint8Array([101,120,112,97,110,100,32,51,50,45,98,121,116,101,32,107]);function x(r,t,e,n,o,i,a){var s,h,f=new Uint8Array(16),c=new Uint8Array(64);for(h=0;h<16;h++)f[h]=0;for(h=0;h<8;h++)f[h]=i[h];for(;o>=64;){for(v(c,f,a,_),h=0;h<64;h++)r[t+h]=e[n+h]^c[h];for(s=1,h=8;h<16;h++)s=s+(255&f[h])|0,f[h]=255&s,s>>>=8;o-=64,t+=64,n+=64}if(o>0)for(v(c,f,a,_),h=0;h<o;h++)r[t+h]=e[n+h]^c[h];return 0}function U(r,t,e,n,o){var i,a,s=new Uint8Array(16),h=new Uint8Array(64);for(a=0;a<16;a++)s[a]=0;for(a=0;a<8;a++)s[a]=n[a];for(;e>=64;){for(v(h,s,o,_),a=0;a<64;a++)r[t+a]=h[a];for(i=1,a=8;a<16;a++)i=i+(255&s[a])|0,s[a]=255&i,i>>>=8;e-=64,t+=64}if(e>0)for(v(h,s,o,_),a=0;a<e;a++)r[t+a]=h[a];return 0}function m(r,t,e,n,o){var i=new Uint8Array(32);A(i,n,o,_);for(var a=new Uint8Array(8),s=0;s<8;s++)a[s]=n[s+16];return U(r,t,e,a,i)}function E(r,t,e,n,o,i,a){var s=new Uint8Array(32);A(s,i,a,_);for(var h=new Uint8Array(8),f=0;f<8;f++)h[f]=i[f+16];return x(r,t,e,n,o,h,s)}var M=function(r){var t,e,n,o,i,a,s,h;this.buffer=new Uint8Array(16),this.r=new Uint16Array(10),this.h=new Uint16Array(10),this.pad=new Uint16Array(8),this.leftover=0,this.fin=0,t=255&r[0]|(255&r[1])<<8,this.r[0]=8191&t,e=255&r[2]|(255&r[3])<<8,this.r[1]=8191&(t>>>13|e<<3),n=255&r[4]|(255&r[5])<<8,this.r[2]=7939&(e>>>10|n<<6),o=255&r[6]|(255&r[7])<<8,this.r[3]=8191&(n>>>7|o<<9),i=255&r[8]|(255&r[9])<<8,this.r[4]=255&(o>>>4|i<<12),this.r[5]=i>>>1&8190,a=255&r[10]|(255&r[11])<<8,this.r[6]=8191&(i>>>14|a<<2),s=255&r[12]|(255&r[13])<<8,this.r[7]=8065&(a>>>11|s<<5),h=255&r[14]|(255&r[15])<<8,this.r[8]=8191&(s>>>8|h<<8),this.r[9]=h>>>5&127,this.pad[0]=255&r[16]|(255&r[17])<<8,this.pad[1]=255&r[18]|(255&r[19])<<8,this.pad[2]=255&r[20]|(255&r[21])<<8,this.pad[3]=255&r[22]|(255&r[23])<<8,this.pad[4]=255&r[24]|(255&r[25])<<8,this.pad[5]=255&r[26]|(255&r[27])<<8,this.pad[6]=255&r[28]|(255&r[29])<<8,this.pad[7]=255&r[30]|(255&r[31])<<8};function K(r,t,e,n,o,i){var a=new M(i);return a.update(e,n,o),a.finish(r,t),0}function B(r,t,e,n,o,i){var a=new Uint8Array(16);return K(a,0,e,n,o,i),b(r,t,a,0)}function S(r,t,e,n,o){var i;if(e<32)return-1;for(E(r,0,t,0,e,n,o),K(r,16,r,32,e-32,r),i=0;i<16;i++)r[i]=0;return 0}function T(r,t,e,n,o){var i,a=new Uint8Array(32);if(e<32)return-1;if(m(a,0,32,n,o),0!==B(t,16,t,32,e-32,a))return-1;for(E(r,0,t,0,e,n,o),i=0;i<32;i++)r[i]=0;return 0}function k(r,t){var e;for(e=0;e<16;e++)r[e]=0|t[e]}function P(r){var t,e,n=1;for(t=0;t<16;t++)e=r[t]+n+65535,n=Math.floor(e/65536),r[t]=e-65536*n;r[0]+=n-1+37*(n-1)}function L(r,t,e){for(var n,o=~(e-1),i=0;i<16;i++)n=o&(r[i]^t[i]),r[i]^=n,t[i]^=n}function Y(r,e){var n,o,i,a=t(),s=t();for(n=0;n<16;n++)s[n]=e[n];for(P(s),P(s),P(s),o=0;o<2;o++){for(a[0]=s[0]-65517,n=1;n<15;n++)a[n]=s[n]-65535-(a[n-1]>>16&1),a[n-1]&=65535;a[15]=s[15]-32767-(a[14]>>16&1),i=a[15]>>16&1,a[14]&=65535,L(s,a,1-i)}for(n=0;n<16;n++)r[2*n]=255&s[n],r[2*n+1]=s[n]>>8}function z(r,t){var e=new Uint8Array(32),n=new Uint8Array(32);return Y(e,r),Y(n,t),g(e,0,n,0)}function O(r){var t=new Uint8Array(32);return Y(t,r),1&t[0]}function R(r,t){var e;for(e=0;e<16;e++)r[e]=t[2*e]+(t[2*e+1]<<8);r[15]&=32767}function C(r,t,e){for(var n=0;n<16;n++)r[n]=t[n]+e[n]}function F(r,t,e){for(var n=0;n<16;n++)r[n]=t[n]-e[n]}function N(r,t,e){var n,o,i=0,a=0,s=0,h=0,f=0,c=0,u=0,y=0,l=0,p=0,d=0,w=0,b=0,g=0,v=0,A=0,_=0,x=0,U=0,m=0,E=0,M=0,K=0,B=0,S=0,T=0,k=0,P=0,L=0,Y=0,z=0,O=e[0],R=e[1],C=e[2],F=e[3],N=e[4],j=e[5],I=e[6],Z=e[7],q=e[8],H=e[9],D=e[10],G=e[11],$=e[12],J=e[13],V=e[14],X=e[15];i+=(n=t[0])*O,a+=n*R,s+=n*C,h+=n*F,f+=n*N,c+=n*j,u+=n*I,y+=n*Z,l+=n*q,p+=n*H,d+=n*D,w+=n*G,b+=n*$,g+=n*J,v+=n*V,A+=n*X,a+=(n=t[1])*O,s+=n*R,h+=n*C,f+=n*F,c+=n*N,u+=n*j,y+=n*I,l+=n*Z,p+=n*q,d+=n*H,w+=n*D,b+=n*G,g+=n*$,v+=n*J,A+=n*V,_+=n*X,s+=(n=t[2])*O,h+=n*R,f+=n*C,c+=n*F,u+=n*N,y+=n*j,l+=n*I,p+=n*Z,d+=n*q,w+=n*H,b+=n*D,g+=n*G,v+=n*$,A+=n*J,_+=n*V,x+=n*X,h+=(n=t[3])*O,f+=n*R,c+=n*C,u+=n*F,y+=n*N,l+=n*j,p+=n*I,d+=n*Z,w+=n*q,b+=n*H,g+=n*D,v+=n*G,A+=n*$,_+=n*J,x+=n*V,U+=n*X,f+=(n=t[4])*O,c+=n*R,u+=n*C,y+=n*F,l+=n*N,p+=n*j,d+=n*I,w+=n*Z,b+=n*q,g+=n*H,v+=n*D,A+=n*G,_+=n*$,x+=n*J,U+=n*V,m+=n*X,c+=(n=t[5])*O,u+=n*R,y+=n*C,l+=n*F,p+=n*N,d+=n*j,w+=n*I,b+=n*Z,g+=n*q,v+=n*H,A+=n*D,_+=n*G,x+=n*$,U+=n*J,m+=n*V,E+=n*X,u+=(n=t[6])*O,y+=n*R,l+=n*C,p+=n*F,d+=n*N,w+=n*j,b+=n*I,g+=n*Z,v+=n*q,A+=n*H,_+=n*D,x+=n*G,U+=n*$,m+=n*J,E+=n*V,M+=n*X,y+=(n=t[7])*O,l+=n*R,p+=n*C,d+=n*F,w+=n*N,b+=n*j,g+=n*I,v+=n*Z,A+=n*q,_+=n*H,x+=n*D,U+=n*G,m+=n*$,E+=n*J,M+=n*V,K+=n*X,l+=(n=t[8])*O,p+=n*R,d+=n*C,w+=n*F,b+=n*N,g+=n*j,v+=n*I,A+=n*Z,_+=n*q,x+=n*H,U+=n*D,m+=n*G,E+=n*$,M+=n*J,K+=n*V,B+=n*X,p+=(n=t[9])*O,d+=n*R,w+=n*C,b+=n*F,g+=n*N,v+=n*j,A+=n*I,_+=n*Z,x+=n*q,U+=n*H,m+=n*D,E+=n*G,M+=n*$,K+=n*J,B+=n*V,S+=n*X,d+=(n=t[10])*O,w+=n*R,b+=n*C,g+=n*F,v+=n*N,A+=n*j,_+=n*I,x+=n*Z,U+=n*q,m+=n*H,E+=n*D,M+=n*G,K+=n*$,B+=n*J,S+=n*V,T+=n*X,w+=(n=t[11])*O,b+=n*R,g+=n*C,v+=n*F,A+=n*N,_+=n*j,x+=n*I,U+=n*Z,m+=n*q,E+=n*H,M+=n*D,K+=n*G,B+=n*$,S+=n*J,T+=n*V,k+=n*X,b+=(n=t[12])*O,g+=n*R,v+=n*C,A+=n*F,_+=n*N,x+=n*j,U+=n*I,m+=n*Z,E+=n*q,M+=n*H,K+=n*D,B+=n*G,S+=n*$,T+=n*J,k+=n*V,P+=n*X,g+=(n=t[13])*O,v+=n*R,A+=n*C,_+=n*F,x+=n*N,U+=n*j,m+=n*I,E+=n*Z,M+=n*q,K+=n*H,B+=n*D,S+=n*G,T+=n*$,k+=n*J,P+=n*V,L+=n*X,v+=(n=t[14])*O,A+=n*R,_+=n*C,x+=n*F,U+=n*N,m+=n*j,E+=n*I,M+=n*Z,K+=n*q,B+=n*H,S+=n*D,T+=n*G,k+=n*$,P+=n*J,L+=n*V,Y+=n*X,A+=(n=t[15])*O,a+=38*(x+=n*C),s+=38*(U+=n*F),h+=38*(m+=n*N),f+=38*(E+=n*j),c+=38*(M+=n*I),u+=38*(K+=n*Z),y+=38*(B+=n*q),l+=38*(S+=n*H),p+=38*(T+=n*D),d+=38*(k+=n*G),w+=38*(P+=n*$),b+=38*(L+=n*J),g+=38*(Y+=n*V),v+=38*(z+=n*X),i=(n=(i+=38*(_+=n*R))+(o=1)+65535)-65536*(o=Math.floor(n/65536)),a=(n=a+o+65535)-65536*(o=Math.floor(n/65536)),s=(n=s+o+65535)-65536*(o=Math.floor(n/65536)),h=(n=h+o+65535)-65536*(o=Math.floor(n/65536)),f=(n=f+o+65535)-65536*(o=Math.floor(n/65536)),c=(n=c+o+65535)-65536*(o=Math.floor(n/65536)),u=(n=u+o+65535)-65536*(o=Math.floor(n/65536)),y=(n=y+o+65535)-65536*(o=Math.floor(n/65536)),l=(n=l+o+65535)-65536*(o=Math.floor(n/65536)),p=(n=p+o+65535)-65536*(o=Math.floor(n/65536)),d=(n=d+o+65535)-65536*(o=Math.floor(n/65536)),w=(n=w+o+65535)-65536*(o=Math.floor(n/65536)),b=(n=b+o+65535)-65536*(o=Math.floor(n/65536)),g=(n=g+o+65535)-65536*(o=Math.floor(n/65536)),v=(n=v+o+65535)-65536*(o=Math.floor(n/65536)),A=(n=A+o+65535)-65536*(o=Math.floor(n/65536)),i=(n=(i+=o-1+37*(o-1))+(o=1)+65535)-65536*(o=Math.floor(n/65536)),a=(n=a+o+65535)-65536*(o=Math.floor(n/65536)),s=(n=s+o+65535)-65536*(o=Math.floor(n/65536)),h=(n=h+o+65535)-65536*(o=Math.floor(n/65536)),f=(n=f+o+65535)-65536*(o=Math.floor(n/65536)),c=(n=c+o+65535)-65536*(o=Math.floor(n/65536)),u=(n=u+o+65535)-65536*(o=Math.floor(n/65536)),y=(n=y+o+65535)-65536*(o=Math.floor(n/65536)),l=(n=l+o+65535)-65536*(o=Math.floor(n/65536)),p=(n=p+o+65535)-65536*(o=Math.floor(n/65536)),d=(n=d+o+65535)-65536*(o=Math.floor(n/65536)),w=(n=w+o+65535)-65536*(o=Math.floor(n/65536)),b=(n=b+o+65535)-65536*(o=Math.floor(n/65536)),g=(n=g+o+65535)-65536*(o=Math.floor(n/65536)),v=(n=v+o+65535)-65536*(o=Math.floor(n/65536)),A=(n=A+o+65535)-65536*(o=Math.floor(n/65536)),i+=o-1+37*(o-1),r[0]=i,r[1]=a,r[2]=s,r[3]=h,r[4]=f,r[5]=c,r[6]=u,r[7]=y,r[8]=l,r[9]=p,r[10]=d,r[11]=w,r[12]=b,r[13]=g,r[14]=v,r[15]=A}function j(r,t){N(r,t,t)}function I(r,e){var n,o=t();for(n=0;n<16;n++)o[n]=e[n];for(n=253;n>=0;n--)j(o,o),2!==n&&4!==n&&N(o,o,e);for(n=0;n<16;n++)r[n]=o[n]}function Z(r,e){var n,o=t();for(n=0;n<16;n++)o[n]=e[n];for(n=250;n>=0;n--)j(o,o),1!==n&&N(o,o,e);for(n=0;n<16;n++)r[n]=o[n]}function q(r,e,n){var o,i,a=new Uint8Array(32),s=new Float64Array(80),h=t(),c=t(),u=t(),y=t(),l=t(),p=t();for(i=0;i<31;i++)a[i]=e[i];for(a[31]=127&e[31]|64,a[0]&=248,R(s,n),i=0;i<16;i++)c[i]=s[i],y[i]=h[i]=u[i]=0;for(h[0]=y[0]=1,i=254;i>=0;--i)L(h,c,o=a[i>>>3]>>>(7&i)&1),L(u,y,o),C(l,h,u),F(h,h,u),C(u,c,y),F(c,c,y),j(y,l),j(p,h),N(h,u,h),N(u,c,l),C(l,h,u),F(h,h,u),j(c,h),F(u,y,p),N(h,u,f),C(h,h,y),N(u,u,h),N(h,y,p),N(y,c,s),j(c,l),L(h,c,o),L(u,y,o);for(i=0;i<16;i++)s[i+16]=h[i],s[i+32]=u[i],s[i+48]=c[i],s[i+64]=y[i];var d=s.subarray(32),w=s.subarray(16);return I(d,d),N(w,w,d),Y(r,w),0}function H(r,t){return q(r,t,i)}function D(r,t){return e(t,32),H(r,t)}function G(r,t,e){var o=new Uint8Array(32);return q(o,e,t),A(r,n,o,_)}M.prototype.blocks=function(r,t,e){for(var n,o,i,a,s,h,f,c,u,y,l,p,d,w,b,g,v,A,_,x=this.fin?0:2048,U=this.h[0],m=this.h[1],E=this.h[2],M=this.h[3],K=this.h[4],B=this.h[5],S=this.h[6],T=this.h[7],k=this.h[8],P=this.h[9],L=this.r[0],Y=this.r[1],z=this.r[2],O=this.r[3],R=this.r[4],C=this.r[5],F=this.r[6],N=this.r[7],j=this.r[8],I=this.r[9];e>=16;)y=u=0,y+=(U+=8191&(n=255&r[t+0]|(255&r[t+1])<<8))*L,y+=(m+=8191&(n>>>13|(o=255&r[t+2]|(255&r[t+3])<<8)<<3))*(5*I),y+=(E+=8191&(o>>>10|(i=255&r[t+4]|(255&r[t+5])<<8)<<6))*(5*j),y+=(M+=8191&(i>>>7|(a=255&r[t+6]|(255&r[t+7])<<8)<<9))*(5*N),u=(y+=(K+=8191&(a>>>4|(s=255&r[t+8]|(255&r[t+9])<<8)<<12))*(5*F))>>>13,y&=8191,y+=(B+=s>>>1&8191)*(5*C),y+=(S+=8191&(s>>>14|(h=255&r[t+10]|(255&r[t+11])<<8)<<2))*(5*R),y+=(T+=8191&(h>>>11|(f=255&r[t+12]|(255&r[t+13])<<8)<<5))*(5*O),y+=(k+=8191&(f>>>8|(c=255&r[t+14]|(255&r[t+15])<<8)<<8))*(5*z),l=u+=(y+=(P+=c>>>5|x)*(5*Y))>>>13,l+=U*Y,l+=m*L,l+=E*(5*I),l+=M*(5*j),u=(l+=K*(5*N))>>>13,l&=8191,l+=B*(5*F),l+=S*(5*C),l+=T*(5*R),l+=k*(5*O),u+=(l+=P*(5*z))>>>13,l&=8191,p=u,p+=U*z,p+=m*Y,p+=E*L,p+=M*(5*I),u=(p+=K*(5*j))>>>13,p&=8191,p+=B*(5*N),p+=S*(5*F),p+=T*(5*C),p+=k*(5*R),d=u+=(p+=P*(5*O))>>>13,d+=U*O,d+=m*z,d+=E*Y,d+=M*L,u=(d+=K*(5*I))>>>13,d&=8191,d+=B*(5*j),d+=S*(5*N),d+=T*(5*F),d+=k*(5*C),w=u+=(d+=P*(5*R))>>>13,w+=U*R,w+=m*O,w+=E*z,w+=M*Y,u=(w+=K*L)>>>13,w&=8191,w+=B*(5*I),w+=S*(5*j),w+=T*(5*N),w+=k*(5*F),b=u+=(w+=P*(5*C))>>>13,b+=U*C,b+=m*R,b+=E*O,b+=M*z,u=(b+=K*Y)>>>13,b&=8191,b+=B*L,b+=S*(5*I),b+=T*(5*j),b+=k*(5*N),g=u+=(b+=P*(5*F))>>>13,g+=U*F,g+=m*C,g+=E*R,g+=M*O,u=(g+=K*z)>>>13,g&=8191,g+=B*Y,g+=S*L,g+=T*(5*I),g+=k*(5*j),v=u+=(g+=P*(5*N))>>>13,v+=U*N,v+=m*F,v+=E*C,v+=M*R,u=(v+=K*O)>>>13,v&=8191,v+=B*z,v+=S*Y,v+=T*L,v+=k*(5*I),A=u+=(v+=P*(5*j))>>>13,A+=U*j,A+=m*N,A+=E*F,A+=M*C,u=(A+=K*R)>>>13,A&=8191,A+=B*O,A+=S*z,A+=T*Y,A+=k*L,_=u+=(A+=P*(5*I))>>>13,_+=U*I,_+=m*j,_+=E*N,_+=M*F,u=(_+=K*C)>>>13,_&=8191,_+=B*R,_+=S*O,_+=T*z,_+=k*Y,U=y=8191&(u=(u=((u+=(_+=P*L)>>>13)<<2)+u|0)+(y&=8191)|0),m=l+=u>>>=13,E=p&=8191,M=d&=8191,K=w&=8191,B=b&=8191,S=g&=8191,T=v&=8191,k=A&=8191,P=_&=8191,t+=16,e-=16;this.h[0]=U,this.h[1]=m,this.h[2]=E,this.h[3]=M,this.h[4]=K,this.h[5]=B,this.h[6]=S,this.h[7]=T,this.h[8]=k,this.h[9]=P},M.prototype.finish=function(r,t){var e,n,o,i,a=new Uint16Array(10);if(this.leftover){for(i=this.leftover,this.buffer[i++]=1;i<16;i++)this.buffer[i]=0;this.fin=1,this.blocks(this.buffer,0,16)}for(e=this.h[1]>>>13,this.h[1]&=8191,i=2;i<10;i++)this.h[i]+=e,e=this.h[i]>>>13,this.h[i]&=8191;for(this.h[0]+=5*e,e=this.h[0]>>>13,this.h[0]&=8191,this.h[1]+=e,e=this.h[1]>>>13,this.h[1]&=8191,this.h[2]+=e,a[0]=this.h[0]+5,e=a[0]>>>13,a[0]&=8191,i=1;i<10;i++)a[i]=this.h[i]+e,e=a[i]>>>13,a[i]&=8191;for(a[9]-=8192,n=(1^e)-1,i=0;i<10;i++)a[i]&=n;for(n=~n,i=0;i<10;i++)this.h[i]=this.h[i]&n|a[i];for(this.h[0]=65535&(this.h[0]|this.h[1]<<13),this.h[1]=65535&(this.h[1]>>>3|this.h[2]<<10),this.h[2]=65535&(this.h[2]>>>6|this.h[3]<<7),this.h[3]=65535&(this.h[3]>>>9|this.h[4]<<4),this.h[4]=65535&(this.h[4]>>>12|this.h[5]<<1|this.h[6]<<14),this.h[5]=65535&(this.h[6]>>>2|this.h[7]<<11),this.h[6]=65535&(this.h[7]>>>5|this.h[8]<<8),this.h[7]=65535&(this.h[8]>>>8|this.h[9]<<5),o=this.h[0]+this.pad[0],this.h[0]=65535&o,i=1;i<8;i++)o=(this.h[i]+this.pad[i]|0)+(o>>>16)|0,this.h[i]=65535&o;r[t+0]=this.h[0]>>>0&255,r[t+1]=this.h[0]>>>8&255,r[t+2]=this.h[1]>>>0&255,r[t+3]=this.h[1]>>>8&255,r[t+4]=this.h[2]>>>0&255,r[t+5]=this.h[2]>>>8&255,r[t+6]=this.h[3]>>>0&255,r[t+7]=this.h[3]>>>8&255,r[t+8]=this.h[4]>>>0&255,r[t+9]=this.h[4]>>>8&255,r[t+10]=this.h[5]>>>0&255,r[t+11]=this.h[5]>>>8&255,r[t+12]=this.h[6]>>>0&255,r[t+13]=this.h[6]>>>8&255,r[t+14]=this.h[7]>>>0&255,r[t+15]=this.h[7]>>>8&255},M.prototype.update=function(r,t,e){var n,o;if(this.leftover){for((o=16-this.leftover)>e&&(o=e),n=0;n<o;n++)this.buffer[this.leftover+n]=r[t+n];if(e-=o,t+=o,this.leftover+=o,this.leftover<16)return;this.blocks(this.buffer,0,16),this.leftover=0}if(e>=16&&(o=e-e%16,this.blocks(r,t,o),t+=o,e-=o),e){for(n=0;n<e;n++)this.buffer[this.leftover+n]=r[t+n];this.leftover+=e}};var $=S,J=T;var V=[1116352408,3609767458,1899447441,602891725,3049323471,3964484399,3921009573,2173295548,961987163,4081628472,1508970993,3053834265,2453635748,2937671579,2870763221,3664609560,3624381080,2734883394,310598401,1164996542,607225278,1323610764,1426881987,3590304994,1925078388,4068182383,2162078206,991336113,2614888103,633803317,3248222580,3479774868,3835390401,2666613458,4022224774,944711139,264347078,2341262773,604807628,2007800933,770255983,1495990901,1249150122,1856431235,1555081692,3175218132,1996064986,2198950837,2554220882,3999719339,2821834349,766784016,2952996808,2566594879,3210313671,3203337956,3336571891,1034457026,3584528711,2466948901,113926993,3758326383,338241895,168717936,666307205,1188179964,773529912,1546045734,1294757372,1522805485,1396182291,2643833823,1695183700,2343527390,1986661051,1014477480,2177026350,1206759142,2456956037,344077627,2730485921,1290863460,2820302411,3158454273,3259730800,3505952657,3345764771,106217008,3516065817,3606008344,3600352804,1432725776,4094571909,1467031594,275423344,851169720,430227734,3100823752,506948616,1363258195,659060556,3750685593,883997877,3785050280,958139571,3318307427,1322822218,3812723403,1537002063,2003034995,1747873779,3602036899,1955562222,1575990012,2024104815,1125592928,2227730452,2716904306,2361852424,442776044,2428436474,593698344,2756734187,3733110249,3204031479,2999351573,3329325298,3815920427,3391569614,3928383900,3515267271,566280711,3940187606,3454069534,4118630271,4000239992,116418474,1914138554,174292421,2731055270,289380356,3203993006,460393269,320620315,685471733,587496836,852142971,1086792851,1017036298,365543100,1126000580,2618297676,1288033470,3409855158,1501505948,4234509866,1607167915,987167468,1816402316,1246189591];function X(r,t,e,n){for(var o,i,a,s,h,f,c,u,y,l,p,d,w,b,g,v,A,_,x,U,m,E,M,K,B,S,T=new Int32Array(16),k=new Int32Array(16),P=r[0],L=r[1],Y=r[2],z=r[3],O=r[4],R=r[5],C=r[6],F=r[7],N=t[0],j=t[1],I=t[2],Z=t[3],q=t[4],H=t[5],D=t[6],G=t[7],$=0;n>=128;){for(x=0;x<16;x++)U=8*x+$,T[x]=e[U+0]<<24|e[U+1]<<16|e[U+2]<<8|e[U+3],k[x]=e[U+4]<<24|e[U+5]<<16|e[U+6]<<8|e[U+7];for(x=0;x<80;x++)if(o=P,i=L,a=Y,s=z,h=O,f=R,c=C,F,y=N,l=j,p=I,d=Z,w=q,b=H,g=D,G,M=65535&(E=G),K=E>>>16,B=65535&(m=F),S=m>>>16,M+=65535&(E=(q>>>14|O<<18)^(q>>>18|O<<14)^(O>>>9|q<<23)),K+=E>>>16,B+=65535&(m=(O>>>14|q<<18)^(O>>>18|q<<14)^(q>>>9|O<<23)),S+=m>>>16,M+=65535&(E=q&H^~q&D),K+=E>>>16,B+=65535&(m=O&R^~O&C),S+=m>>>16,m=V[2*x],M+=65535&(E=V[2*x+1]),K+=E>>>16,B+=65535&m,S+=m>>>16,m=T[x%16],K+=(E=k[x%16])>>>16,B+=65535&m,S+=m>>>16,B+=(K+=(M+=65535&E)>>>16)>>>16,M=65535&(E=_=65535&M|K<<16),K=E>>>16,B=65535&(m=A=65535&B|(S+=B>>>16)<<16),S=m>>>16,M+=65535&(E=(N>>>28|P<<4)^(P>>>2|N<<30)^(P>>>7|N<<25)),K+=E>>>16,B+=65535&(m=(P>>>28|N<<4)^(N>>>2|P<<30)^(N>>>7|P<<25)),S+=m>>>16,K+=(E=N&j^N&I^j&I)>>>16,B+=65535&(m=P&L^P&Y^L&Y),S+=m>>>16,u=65535&(B+=(K+=(M+=65535&E)>>>16)>>>16)|(S+=B>>>16)<<16,v=65535&M|K<<16,M=65535&(E=d),K=E>>>16,B=65535&(m=s),S=m>>>16,K+=(E=_)>>>16,B+=65535&(m=A),S+=m>>>16,L=o,Y=i,z=a,O=s=65535&(B+=(K+=(M+=65535&E)>>>16)>>>16)|(S+=B>>>16)<<16,R=h,C=f,F=c,P=u,j=y,I=l,Z=p,q=d=65535&M|K<<16,H=w,D=b,G=g,N=v,x%16==15)for(U=0;U<16;U++)m=T[U],M=65535&(E=k[U]),K=E>>>16,B=65535&m,S=m>>>16,m=T[(U+9)%16],M+=65535&(E=k[(U+9)%16]),K+=E>>>16,B+=65535&m,S+=m>>>16,A=T[(U+1)%16],M+=65535&(E=((_=k[(U+1)%16])>>>1|A<<31)^(_>>>8|A<<24)^(_>>>7|A<<25)),K+=E>>>16,B+=65535&(m=(A>>>1|_<<31)^(A>>>8|_<<24)^A>>>7),S+=m>>>16,A=T[(U+14)%16],K+=(E=((_=k[(U+14)%16])>>>19|A<<13)^(A>>>29|_<<3)^(_>>>6|A<<26))>>>16,B+=65535&(m=(A>>>19|_<<13)^(_>>>29|A<<3)^A>>>6),S+=m>>>16,S+=(B+=(K+=(M+=65535&E)>>>16)>>>16)>>>16,T[U]=65535&B|S<<16,k[U]=65535&M|K<<16;M=65535&(E=N),K=E>>>16,B=65535&(m=P),S=m>>>16,m=r[0],K+=(E=t[0])>>>16,B+=65535&m,S+=m>>>16,S+=(B+=(K+=(M+=65535&E)>>>16)>>>16)>>>16,r[0]=P=65535&B|S<<16,t[0]=N=65535&M|K<<16,M=65535&(E=j),K=E>>>16,B=65535&(m=L),S=m>>>16,m=r[1],K+=(E=t[1])>>>16,B+=65535&m,S+=m>>>16,S+=(B+=(K+=(M+=65535&E)>>>16)>>>16)>>>16,r[1]=L=65535&B|S<<16,t[1]=j=65535&M|K<<16,M=65535&(E=I),K=E>>>16,B=65535&(m=Y),S=m>>>16,m=r[2],K+=(E=t[2])>>>16,B+=65535&m,S+=m>>>16,S+=(B+=(K+=(M+=65535&E)>>>16)>>>16)>>>16,r[2]=Y=65535&B|S<<16,t[2]=I=65535&M|K<<16,M=65535&(E=Z),K=E>>>16,B=65535&(m=z),S=m>>>16,m=r[3],K+=(E=t[3])>>>16,B+=65535&m,S+=m>>>16,S+=(B+=(K+=(M+=65535&E)>>>16)>>>16)>>>16,r[3]=z=65535&B|S<<16,t[3]=Z=65535&M|K<<16,M=65535&(E=q),K=E>>>16,B=65535&(m=O),S=m>>>16,m=r[4],K+=(E=t[4])>>>16,B+=65535&m,S+=m>>>16,S+=(B+=(K+=(M+=65535&E)>>>16)>>>16)>>>16,r[4]=O=65535&B|S<<16,t[4]=q=65535&M|K<<16,M=65535&(E=H),K=E>>>16,B=65535&(m=R),S=m>>>16,m=r[5],K+=(E=t[5])>>>16,B+=65535&m,S+=m>>>16,S+=(B+=(K+=(M+=65535&E)>>>16)>>>16)>>>16,r[5]=R=65535&B|S<<16,t[5]=H=65535&M|K<<16,M=65535&(E=D),K=E>>>16,B=65535&(m=C),S=m>>>16,m=r[6],K+=(E=t[6])>>>16,B+=65535&m,S+=m>>>16,S+=(B+=(K+=(M+=65535&E)>>>16)>>>16)>>>16,r[6]=C=65535&B|S<<16,t[6]=D=65535&M|K<<16,M=65535&(E=G),K=E>>>16,B=65535&(m=F),S=m>>>16,m=r[7],K+=(E=t[7])>>>16,B+=65535&m,S+=m>>>16,S+=(B+=(K+=(M+=65535&E)>>>16)>>>16)>>>16,r[7]=F=65535&B|S<<16,t[7]=G=65535&M|K<<16,$+=128,n-=128}return n}function Q(r,t,e){var n,o=new Int32Array(8),i=new Int32Array(8),a=new Uint8Array(256),s=e;for(o[0]=1779033703,o[1]=3144134277,o[2]=1013904242,o[3]=2773480762,o[4]=1359893119,o[5]=2600822924,o[6]=528734635,o[7]=1541459225,i[0]=4089235720,i[1]=2227873595,i[2]=4271175723,i[3]=1595750129,i[4]=2917565137,i[5]=725511199,i[6]=4215389547,i[7]=327033209,X(o,i,t,e),e%=128,n=0;n<e;n++)a[n]=t[s-e+n];for(a[e]=128,a[(e=256-128*(e<112?1:0))-9]=0,d(a,e-8,s/536870912|0,s<<3),X(o,i,a,e),n=0;n<8;n++)d(r,8*n,o[n],i[n]);return 0}function W(r,e){var n=t(),o=t(),i=t(),a=t(),s=t(),h=t(),f=t(),c=t(),y=t();F(n,r[1],r[0]),F(y,e[1],e[0]),N(n,n,y),C(o,r[0],r[1]),C(y,e[0],e[1]),N(o,o,y),N(i,r[3],e[3]),N(i,i,u),N(a,r[2],e[2]),C(a,a,a),F(s,o,n),F(h,a,i),C(f,a,i),C(c,o,n),N(r[0],s,h),N(r[1],c,f),N(r[2],f,h),N(r[3],s,c)}function rr(r,t,e){var n;for(n=0;n<4;n++)L(r[n],t[n],e)}function tr(r,e){var n=t(),o=t(),i=t();I(i,e[2]),N(n,e[0],i),N(o,e[1],i),Y(r,o),r[31]^=O(n)<<7}function er(r,t,e){var n,o;for(k(r[0],s),k(r[1],h),k(r[2],h),k(r[3],s),o=255;o>=0;--o)rr(r,t,n=e[o/8|0]>>(7&o)&1),W(t,r),W(r,r),rr(r,t,n)}function nr(r,e){var n=[t(),t(),t(),t()];k(n[0],y),k(n[1],l),k(n[2],h),N(n[3],y,l),er(r,n,e)}function or(r,n,o){var i,a=new Uint8Array(64),s=[t(),t(),t(),t()];for(o||e(n,32),Q(a,n,32),a[0]&=248,a[31]&=127,a[31]|=64,nr(s,a),tr(r,s),i=0;i<32;i++)n[i+32]=r[i];return 0}var ir=new Float64Array([237,211,245,92,26,99,18,88,214,156,247,162,222,249,222,20,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,16]);function ar(r,t){var e,n,o,i;for(n=63;n>=32;--n){for(e=0,o=n-32,i=n-12;o<i;++o)t[o]+=e-16*t[n]*ir[o-(n-32)],e=Math.floor((t[o]+128)/256),t[o]-=256*e;t[o]+=e,t[n]=0}for(e=0,o=0;o<32;o++)t[o]+=e-(t[31]>>4)*ir[o],e=t[o]>>8,t[o]&=255;for(o=0;o<32;o++)t[o]-=e*ir[o];for(n=0;n<32;n++)t[n+1]+=t[n]>>8,r[n]=255&t[n]}function sr(r){var t,e=new Float64Array(64);for(t=0;t<64;t++)e[t]=r[t];for(t=0;t<64;t++)r[t]=0;ar(r,e)}function hr(r,e,n,o){var i,a,s=new Uint8Array(64),h=new Uint8Array(64),f=new Uint8Array(64),c=new Float64Array(64),u=[t(),t(),t(),t()];Q(s,o,32),s[0]&=248,s[31]&=127,s[31]|=64;var y=n+64;for(i=0;i<n;i++)r[64+i]=e[i];for(i=0;i<32;i++)r[32+i]=s[32+i];for(Q(f,r.subarray(32),n+32),sr(f),nr(u,f),tr(r,u),i=32;i<64;i++)r[i]=o[i];for(Q(h,r,n+64),sr(h),i=0;i<64;i++)c[i]=0;for(i=0;i<32;i++)c[i]=f[i];for(i=0;i<32;i++)for(a=0;a<32;a++)c[i+a]+=h[i]*s[a];return ar(r.subarray(32),c),y}function fr(r,e,n,o){var i,a=new Uint8Array(32),f=new Uint8Array(64),u=[t(),t(),t(),t()],y=[t(),t(),t(),t()];if(n<64)return-1;if(function(r,e){var n=t(),o=t(),i=t(),a=t(),f=t(),u=t(),y=t();return k(r[2],h),R(r[1],e),j(i,r[1]),N(a,i,c),F(i,i,r[2]),C(a,r[2],a),j(f,a),j(u,f),N(y,u,f),N(n,y,i),N(n,n,a),Z(n,n),N(n,n,i),N(n,n,a),N(n,n,a),N(r[0],n,a),j(o,r[0]),N(o,o,a),z(o,i)&&N(r[0],r[0],p),j(o,r[0]),N(o,o,a),z(o,i)?-1:(O(r[0])===e[31]>>7&&F(r[0],s,r[0]),N(r[3],r[0],r[1]),0)}(y,o))return-1;for(i=0;i<n;i++)r[i]=e[i];for(i=0;i<32;i++)r[i+32]=o[i];if(Q(f,r,n),sr(f),er(u,y,f),nr(y,e.subarray(32)),W(u,y),tr(a,u),n-=64,g(e,0,a,0)){for(i=0;i<n;i++)r[i]=0;return-1}for(i=0;i<n;i++)r[i]=e[i+64];return n}var cr=16,ur=64,yr=32,lr=64;function pr(r,t){if(32!==r.length)throw new Error("bad key size");if(24!==t.length)throw new Error("bad nonce size")}function dr(){for(var r=0;r<arguments.length;r++)if(!(arguments[r]instanceof Uint8Array))throw new TypeError("unexpected type, use Uint8Array")}function wr(r){for(var t=0;t<r.length;t++)r[t]=0}r.lowlevel={crypto_core_hsalsa20:A,crypto_stream_xor:E,crypto_stream:m,crypto_stream_salsa20_xor:x,crypto_stream_salsa20:U,crypto_onetimeauth:K,crypto_onetimeauth_verify:B,crypto_verify_16:b,crypto_verify_32:g,crypto_secretbox:S,crypto_secretbox_open:T,crypto_scalarmult:q,crypto_scalarmult_base:H,crypto_box_beforenm:G,crypto_box_afternm:$,crypto_box:function(r,t,e,n,o,i){var a=new Uint8Array(32);return G(a,o,i),$(r,t,e,n,a)},crypto_box_open:function(r,t,e,n,o,i){var a=new Uint8Array(32);return G(a,o,i),J(r,t,e,n,a)},crypto_box_keypair:D,crypto_hash:Q,crypto_sign:hr,crypto_sign_keypair:or,crypto_sign_open:fr,crypto_secretbox_KEYBYTES:32,crypto_secretbox_NONCEBYTES:24,crypto_secretbox_ZEROBYTES:32,crypto_secretbox_BOXZEROBYTES:cr,crypto_scalarmult_BYTES:32,crypto_scalarmult_SCALARBYTES:32,crypto_box_PUBLICKEYBYTES:32,crypto_box_SECRETKEYBYTES:32,crypto_box_BEFORENMBYTES:32,crypto_box_NONCEBYTES:24,crypto_box_ZEROBYTES:32,crypto_box_BOXZEROBYTES:16,crypto_sign_BYTES:ur,crypto_sign_PUBLICKEYBYTES:yr,crypto_sign_SECRETKEYBYTES:lr,crypto_sign_SEEDBYTES:32,crypto_hash_BYTES:64,gf:t,D:c,L:ir,pack25519:Y,unpack25519:R,M:N,A:C,S:j,Z:F,pow2523:Z,add:W,set25519:k,modL:ar,scalarmult:er,scalarbase:nr},r.randomBytes=function(r){var t=new Uint8Array(r);return e(t,r),t},r.secretbox=function(r,t,e){dr(r,t,e),pr(e,t);for(var n=new Uint8Array(32+r.length),o=new Uint8Array(n.length),i=0;i<r.length;i++)n[i+32]=r[i];return S(o,n,n.length,t,e),o.subarray(cr)},r.secretbox.open=function(r,t,e){dr(r,t,e),pr(e,t);for(var n=new Uint8Array(cr+r.length),o=new Uint8Array(n.length),i=0;i<r.length;i++)n[i+cr]=r[i];return n.length<32||0!==T(o,n,n.length,t,e)?null:o.subarray(32)},r.secretbox.keyLength=32,r.secretbox.nonceLength=24,r.secretbox.overheadLength=cr,r.scalarMult=function(r,t){if(dr(r,t),32!==r.length)throw new Error("bad n size");if(32!==t.length)throw new Error("bad p size");var e=new Uint8Array(32);return q(e,r,t),e},r.scalarMult.base=function(r){if(dr(r),32!==r.length)throw new Error("bad n size");var t=new Uint8Array(32);return H(t,r),t},r.scalarMult.scalarLength=32,r.scalarMult.groupElementLength=32,r.box=function(t,e,n,o){var i=r.box.before(n,o);return r.secretbox(t,e,i)},r.box.before=function(r,t){dr(r,t),function(r,t){if(32!==r.length)throw new Error("bad public key size");if(32!==t.length)throw new Error("bad secret key size")}(r,t);var e=new Uint8Array(32);return G(e,r,t),e},r.box.after=r.secretbox,r.box.open=function(t,e,n,o){var i=r.box.before(n,o);return r.secretbox.open(t,e,i)},r.box.open.after=r.secretbox.open,r.box.keyPair=function(){var r=new Uint8Array(32),t=new Uint8Array(32);return D(r,t),{publicKey:r,secretKey:t}},r.box.keyPair.fromSecretKey=function(r){if(dr(r),32!==r.length)throw new Error("bad secret key size");var t=new Uint8Array(32);return H(t,r),{publicKey:t,secretKey:new Uint8Array(r)}},r.box.publicKeyLength=32,r.box.secretKeyLength=32,r.box.sharedKeyLength=32,r.box.nonceLength=24,r.box.overheadLength=r.secretbox.overheadLength,r.sign=function(r,t){if(dr(r,t),t.length!==lr)throw new Error("bad secret key size");var e=new Uint8Array(ur+r.length);return hr(e,r,r.length,t),e},r.sign.open=function(r,t){if(dr(r,t),t.length!==yr)throw new Error("bad public key size");var e=new Uint8Array(r.length),n=fr(e,r,r.length,t);if(n<0)return null;for(var o=new Uint8Array(n),i=0;i<o.length;i++)o[i]=e[i];return o},r.sign.detached=function(t,e){for(var n=r.sign(t,e),o=new Uint8Array(ur),i=0;i<o.length;i++)o[i]=n[i];return o},r.sign.detached.verify=function(r,t,e){if(dr(r,t,e),t.length!==ur)throw new Error("bad signature size");if(e.length!==yr)throw new Error("bad public key size");var n,o=new Uint8Array(ur+r.length),i=new Uint8Array(ur+r.length);for(n=0;n<ur;n++)o[n]=t[n];for(n=0;n<r.length;n++)o[n+ur]=r[n];return fr(i,o,o.length,e)>=0},r.sign.keyPair=function(){var r=new Uint8Array(yr),t=new Uint8Array(lr);return or(r,t),{publicKey:r,secretKey:t}},r.sign.keyPair.fromSecretKey=function(r){if(dr(r),r.length!==lr)throw new Error("bad secret key size");for(var t=new Uint8Array(yr),e=0;e<t.length;e++)t[e]=r[32+e];return{publicKey:t,secretKey:new Uint8Array(r)}},r.sign.keyPair.fromSeed=function(r){if(dr(r),32!==r.length)throw new Error("bad seed size");for(var t=new Uint8Array(yr),e=new Uint8Array(lr),n=0;n<32;n++)e[n]=r[n];return or(t,e,!0),{publicKey:t,secretKey:e}},r.sign.publicKeyLength=yr,r.sign.secretKeyLength=lr,r.sign.seedLength=32,r.sign.signatureLength=ur,r.hash=function(r){dr(r);var t=new Uint8Array(64);return Q(t,r,r.length),t},r.hash.hashLength=64,r.verify=function(r,t){return dr(r,t),0!==r.length&&0!==t.length&&(r.length===t.length&&0===w(r,0,t,0,r.length))},r.setPRNG=function(r){e=r},function(){var t="undefined"!=typeof self?self.crypto||self.msCrypto:null;if(t&&t.getRandomValues){r.setPRNG((function(r,e){var n,o=new Uint8Array(e);for(n=0;n<e;n+=65536)t.getRandomValues(o.subarray(n,n+Math.min(e-n,65536)));for(n=0;n<e;n++)r[n]=o[n];wr(o)}))}else void 0!==o&&(t=a)&&t.randomBytes&&r.setPRNG((function(r,e){var n,o=t.randomBytes(e);for(n=0;n<e;n++)r[n]=o[n];wr(o)}))}()}(r.exports?r.exports:self.nacl=self.nacl||{})}(i);var s=e(i.exports),h={exports:{}};!function(r){var e,n;e=t,n=function(){var r={};function t(r){if(!/^(?:[A-Za-z0-9+\/]{2}[A-Za-z0-9+\/]{2})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/.test(r))throw new TypeError("invalid encoding")}return r.decodeUTF8=function(r){if("string"!=typeof r)throw new TypeError("expected string");var t,e=unescape(encodeURIComponent(r)),n=new Uint8Array(e.length);for(t=0;t<e.length;t++)n[t]=e.charCodeAt(t);return n},r.encodeUTF8=function(r){var t,e=[];for(t=0;t<r.length;t++)e.push(String.fromCharCode(r[t]));return decodeURIComponent(escape(e.join("")))},"undefined"==typeof atob?void 0!==Buffer.from?(r.encodeBase64=function(r){return Buffer.from(r).toString("base64")},r.decodeBase64=function(r){return t(r),new Uint8Array(Array.prototype.slice.call(Buffer.from(r,"base64"),0))}):(r.encodeBase64=function(r){return new Buffer(r).toString("base64")},r.decodeBase64=function(r){return t(r),new Uint8Array(Array.prototype.slice.call(new Buffer(r,"base64"),0))}):(r.encodeBase64=function(r){var t,e=[],n=r.length;for(t=0;t<n;t++)e.push(String.fromCharCode(r[t]));return btoa(e.join(""))},r.decodeBase64=function(r){t(r);var e,n=atob(r),o=new Uint8Array(n.length);for(e=0;e<n.length;e++)o[e]=n.charCodeAt(e);return o}),r},r.exports?r.exports=n():(e.nacl||(e.nacl={}),e.nacl.util=n())}(h);var f=e(h.exports);const c=s;c.util=f;function u({publicKeyHex:r,publicKey:t},e,n){if("x25519-xsalsa20-poly1305"===n){if("string"!=typeof e.data)throw new Error('Cannot detect secret message, message params should be of the form {data: "secret message"} ');const n=c.box.keyPair();let o;if(t)try{o=c.util.decodeBase64(t)}catch(r){throw new Error("Bad public key")}else{if(!r)throw new Error("No public key");try{o=w(r)}catch(r){throw new Error("Bad public key")}}const i=c.util.decodeUTF8(e.data),a=c.randomBytes(c.box.nonceLength),s=c.box(i,a,o,n.secretKey);return{version:"x25519-xsalsa20-poly1305",nonce:c.util.encodeBase64(a),ephemPublicKey:c.util.encodeBase64(n.publicKey),ciphertext:c.util.encodeBase64(s)}}throw new Error("Encryption type/version not supported")}function y(r,t){if("x25519-xsalsa20-poly1305"===r.version){const e=w(t),n=c.box.keyPair.fromSecretKey(e).secretKey,o=c.util.decodeBase64(r.nonce),i=c.util.decodeBase64(r.ciphertext),a=c.util.decodeBase64(r.ephemPublicKey),s=c.box.open(i,o,a,n);let h;try{h=c.util.encodeUTF8(s)}catch(r){throw new Error("Decryption failed.")}if(h)return h;throw new Error("Decryption failed.")}throw new Error("Encryption type/version not supported.")}const l=(r,t,e="hex")=>{try{const n=c.sign(c.util.decodeUTF8(r),w(t));return"base64"==e?c.util.encodeBase64(n):d(n)}catch(r){console.error(r.message)}},p=(r,t,e="hex")=>{try{const n=c.sign.open("base64"==e?c.util.decodeUTF8(r):w(r),w(t));return c.util.encodeUTF8(n)}catch(r){console.error(r.message)}};function d(r){return Array.from(new Uint8Array(r)).map((r=>r.toString(16).padStart(2,"0"))).join("")}function w(r){const t=r.match(/.{1,2}(?=(.{2})+(?!.))|.{1,2}$/g);return new Uint8Array(t.map((r=>parseInt(r,16))))}const b=async()=>{if(await v())try{return await window.ethereum.request({method:"eth_getEncryptionPublicKey",params:[window.ethereum.selectedAddress]})}catch(r){console.error(r)}},g="undefined"!=typeof window&&window.ethereum?.isMetaMask,v=async()=>{if(g)try{return await window.ethereum.request({method:"eth_requestAccounts"})}catch(r){console.error(r)}};r._decrypt=y,r._encrypt=u,r.bufferToHex=d,r.decrypt=async(r,t)=>{const e=w(r),n=JSON.parse(c.util.encodeUTF8(e));let o;try{t?o=y(n,t):(await v(),o=await window.ethereum.request({method:"eth_decrypt",params:["0x"+r,window.ethereum.selectedAddress]}))}catch(r){console.error(r)}return o},r.encrypt=async(r="message",t)=>{let e;if(t||(e=await b()),!e&&!t)return;const n=u({publicKey:e,publicKeyHex:t},{data:r},"x25519-xsalsa20-poly1305");return d(c.util.decodeUTF8(JSON.stringify(n)))},r.getMetaMaskPublicKey=b,r.hexToBuffer=w,r.isMetaMask=g,r.keyPair=r=>{if(1==r){const r=c.sign.keyPair();return{signPublicKey:r.publicKey,signSecretKey:r.secretKey,signPublicKeyHex:d(r.publicKey),signSecretKeyHex:d(r.secretKey)}}{const r=c.box.keyPair(),t=d(r.publicKey),e=d(r.secretKey);return{privateKey:r.secretKey,publicKey:r.publicKey,privateKeyHex:e,publicKeyHex:t}}},r.nacl=c,r.random=()=>Math.floor(2147483648*Math.random()).toString(36),r.sign=l,r.signMultiple=(r,t,e)=>t.reduce(((r,t)=>l(r,t,e)),r),r.verifySignature=p,r.verifySignatures=(r,t,e)=>t.reduce(((r,t)=>p(r,t,e)),r)}));
