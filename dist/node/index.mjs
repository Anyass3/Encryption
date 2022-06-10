import r from"crypto";var t="undefined"!=typeof globalThis?globalThis:"undefined"!=typeof window?window:"undefined"!=typeof global?global:"undefined"!=typeof self?self:{};var e={exports:{}};!function(t){var e=function(r){var t,e=new Float64Array(16);if(r)for(t=0;t<r.length;t++)e[t]=r[t];return e},n=function(){throw new Error("no PRNG")},o=new Uint8Array(16),i=new Uint8Array(32);i[0]=9;var a=e(),h=e([1]),s=e([56129,1]),f=e([30883,4953,19914,30187,55467,16705,2637,112,59544,30585,16505,36039,65139,11119,27886,20995]),c=e([61785,9906,39828,60374,45398,33411,5274,224,53552,61171,33010,6542,64743,22239,55772,9222]),u=e([54554,36645,11616,51542,42930,38181,51040,26924,56412,64982,57905,49316,21502,52590,14035,8553]),y=e([26200,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214]),l=e([41136,18958,6951,50414,58488,44335,6150,12099,55207,15867,153,11085,57099,20417,9344,11139]);function p(r,t,e,n){r[t]=e>>24&255,r[t+1]=e>>16&255,r[t+2]=e>>8&255,r[t+3]=255&e,r[t+4]=n>>24&255,r[t+5]=n>>16&255,r[t+6]=n>>8&255,r[t+7]=255&n}function w(r,t,e,n,o){var i,a=0;for(i=0;i<o;i++)a|=r[t+i]^e[n+i];return(1&a-1>>>8)-1}function b(r,t,e,n){return w(r,t,e,n,16)}function d(r,t,e,n){return w(r,t,e,n,32)}function g(r,t,e,n){!function(r,t,e,n){for(var o,i=255&n[0]|(255&n[1])<<8|(255&n[2])<<16|(255&n[3])<<24,a=255&e[0]|(255&e[1])<<8|(255&e[2])<<16|(255&e[3])<<24,h=255&e[4]|(255&e[5])<<8|(255&e[6])<<16|(255&e[7])<<24,s=255&e[8]|(255&e[9])<<8|(255&e[10])<<16|(255&e[11])<<24,f=255&e[12]|(255&e[13])<<8|(255&e[14])<<16|(255&e[15])<<24,c=255&n[4]|(255&n[5])<<8|(255&n[6])<<16|(255&n[7])<<24,u=255&t[0]|(255&t[1])<<8|(255&t[2])<<16|(255&t[3])<<24,y=255&t[4]|(255&t[5])<<8|(255&t[6])<<16|(255&t[7])<<24,l=255&t[8]|(255&t[9])<<8|(255&t[10])<<16|(255&t[11])<<24,p=255&t[12]|(255&t[13])<<8|(255&t[14])<<16|(255&t[15])<<24,w=255&n[8]|(255&n[9])<<8|(255&n[10])<<16|(255&n[11])<<24,b=255&e[16]|(255&e[17])<<8|(255&e[18])<<16|(255&e[19])<<24,d=255&e[20]|(255&e[21])<<8|(255&e[22])<<16|(255&e[23])<<24,g=255&e[24]|(255&e[25])<<8|(255&e[26])<<16|(255&e[27])<<24,v=255&e[28]|(255&e[29])<<8|(255&e[30])<<16|(255&e[31])<<24,A=255&n[12]|(255&n[13])<<8|(255&n[14])<<16|(255&n[15])<<24,U=i,x=a,_=h,E=s,m=f,K=c,B=u,M=y,S=l,T=p,k=w,L=b,Y=d,P=g,z=v,C=A,R=0;R<20;R+=2)U^=(o=(Y^=(o=(S^=(o=(m^=(o=U+Y|0)<<7|o>>>25)+U|0)<<9|o>>>23)+m|0)<<13|o>>>19)+S|0)<<18|o>>>14,K^=(o=(x^=(o=(P^=(o=(T^=(o=K+x|0)<<7|o>>>25)+K|0)<<9|o>>>23)+T|0)<<13|o>>>19)+P|0)<<18|o>>>14,k^=(o=(B^=(o=(_^=(o=(z^=(o=k+B|0)<<7|o>>>25)+k|0)<<9|o>>>23)+z|0)<<13|o>>>19)+_|0)<<18|o>>>14,C^=(o=(L^=(o=(M^=(o=(E^=(o=C+L|0)<<7|o>>>25)+C|0)<<9|o>>>23)+E|0)<<13|o>>>19)+M|0)<<18|o>>>14,U^=(o=(E^=(o=(_^=(o=(x^=(o=U+E|0)<<7|o>>>25)+U|0)<<9|o>>>23)+x|0)<<13|o>>>19)+_|0)<<18|o>>>14,K^=(o=(m^=(o=(M^=(o=(B^=(o=K+m|0)<<7|o>>>25)+K|0)<<9|o>>>23)+B|0)<<13|o>>>19)+M|0)<<18|o>>>14,k^=(o=(T^=(o=(S^=(o=(L^=(o=k+T|0)<<7|o>>>25)+k|0)<<9|o>>>23)+L|0)<<13|o>>>19)+S|0)<<18|o>>>14,C^=(o=(z^=(o=(P^=(o=(Y^=(o=C+z|0)<<7|o>>>25)+C|0)<<9|o>>>23)+Y|0)<<13|o>>>19)+P|0)<<18|o>>>14;U=U+i|0,x=x+a|0,_=_+h|0,E=E+s|0,m=m+f|0,K=K+c|0,B=B+u|0,M=M+y|0,S=S+l|0,T=T+p|0,k=k+w|0,L=L+b|0,Y=Y+d|0,P=P+g|0,z=z+v|0,C=C+A|0,r[0]=U>>>0&255,r[1]=U>>>8&255,r[2]=U>>>16&255,r[3]=U>>>24&255,r[4]=x>>>0&255,r[5]=x>>>8&255,r[6]=x>>>16&255,r[7]=x>>>24&255,r[8]=_>>>0&255,r[9]=_>>>8&255,r[10]=_>>>16&255,r[11]=_>>>24&255,r[12]=E>>>0&255,r[13]=E>>>8&255,r[14]=E>>>16&255,r[15]=E>>>24&255,r[16]=m>>>0&255,r[17]=m>>>8&255,r[18]=m>>>16&255,r[19]=m>>>24&255,r[20]=K>>>0&255,r[21]=K>>>8&255,r[22]=K>>>16&255,r[23]=K>>>24&255,r[24]=B>>>0&255,r[25]=B>>>8&255,r[26]=B>>>16&255,r[27]=B>>>24&255,r[28]=M>>>0&255,r[29]=M>>>8&255,r[30]=M>>>16&255,r[31]=M>>>24&255,r[32]=S>>>0&255,r[33]=S>>>8&255,r[34]=S>>>16&255,r[35]=S>>>24&255,r[36]=T>>>0&255,r[37]=T>>>8&255,r[38]=T>>>16&255,r[39]=T>>>24&255,r[40]=k>>>0&255,r[41]=k>>>8&255,r[42]=k>>>16&255,r[43]=k>>>24&255,r[44]=L>>>0&255,r[45]=L>>>8&255,r[46]=L>>>16&255,r[47]=L>>>24&255,r[48]=Y>>>0&255,r[49]=Y>>>8&255,r[50]=Y>>>16&255,r[51]=Y>>>24&255,r[52]=P>>>0&255,r[53]=P>>>8&255,r[54]=P>>>16&255,r[55]=P>>>24&255,r[56]=z>>>0&255,r[57]=z>>>8&255,r[58]=z>>>16&255,r[59]=z>>>24&255,r[60]=C>>>0&255,r[61]=C>>>8&255,r[62]=C>>>16&255,r[63]=C>>>24&255}(r,t,e,n)}function v(r,t,e,n){!function(r,t,e,n){for(var o,i=255&n[0]|(255&n[1])<<8|(255&n[2])<<16|(255&n[3])<<24,a=255&e[0]|(255&e[1])<<8|(255&e[2])<<16|(255&e[3])<<24,h=255&e[4]|(255&e[5])<<8|(255&e[6])<<16|(255&e[7])<<24,s=255&e[8]|(255&e[9])<<8|(255&e[10])<<16|(255&e[11])<<24,f=255&e[12]|(255&e[13])<<8|(255&e[14])<<16|(255&e[15])<<24,c=255&n[4]|(255&n[5])<<8|(255&n[6])<<16|(255&n[7])<<24,u=255&t[0]|(255&t[1])<<8|(255&t[2])<<16|(255&t[3])<<24,y=255&t[4]|(255&t[5])<<8|(255&t[6])<<16|(255&t[7])<<24,l=255&t[8]|(255&t[9])<<8|(255&t[10])<<16|(255&t[11])<<24,p=255&t[12]|(255&t[13])<<8|(255&t[14])<<16|(255&t[15])<<24,w=255&n[8]|(255&n[9])<<8|(255&n[10])<<16|(255&n[11])<<24,b=255&e[16]|(255&e[17])<<8|(255&e[18])<<16|(255&e[19])<<24,d=255&e[20]|(255&e[21])<<8|(255&e[22])<<16|(255&e[23])<<24,g=255&e[24]|(255&e[25])<<8|(255&e[26])<<16|(255&e[27])<<24,v=255&e[28]|(255&e[29])<<8|(255&e[30])<<16|(255&e[31])<<24,A=255&n[12]|(255&n[13])<<8|(255&n[14])<<16|(255&n[15])<<24,U=0;U<20;U+=2)i^=(o=(d^=(o=(l^=(o=(f^=(o=i+d|0)<<7|o>>>25)+i|0)<<9|o>>>23)+f|0)<<13|o>>>19)+l|0)<<18|o>>>14,c^=(o=(a^=(o=(g^=(o=(p^=(o=c+a|0)<<7|o>>>25)+c|0)<<9|o>>>23)+p|0)<<13|o>>>19)+g|0)<<18|o>>>14,w^=(o=(u^=(o=(h^=(o=(v^=(o=w+u|0)<<7|o>>>25)+w|0)<<9|o>>>23)+v|0)<<13|o>>>19)+h|0)<<18|o>>>14,A^=(o=(b^=(o=(y^=(o=(s^=(o=A+b|0)<<7|o>>>25)+A|0)<<9|o>>>23)+s|0)<<13|o>>>19)+y|0)<<18|o>>>14,i^=(o=(s^=(o=(h^=(o=(a^=(o=i+s|0)<<7|o>>>25)+i|0)<<9|o>>>23)+a|0)<<13|o>>>19)+h|0)<<18|o>>>14,c^=(o=(f^=(o=(y^=(o=(u^=(o=c+f|0)<<7|o>>>25)+c|0)<<9|o>>>23)+u|0)<<13|o>>>19)+y|0)<<18|o>>>14,w^=(o=(p^=(o=(l^=(o=(b^=(o=w+p|0)<<7|o>>>25)+w|0)<<9|o>>>23)+b|0)<<13|o>>>19)+l|0)<<18|o>>>14,A^=(o=(v^=(o=(g^=(o=(d^=(o=A+v|0)<<7|o>>>25)+A|0)<<9|o>>>23)+d|0)<<13|o>>>19)+g|0)<<18|o>>>14;r[0]=i>>>0&255,r[1]=i>>>8&255,r[2]=i>>>16&255,r[3]=i>>>24&255,r[4]=c>>>0&255,r[5]=c>>>8&255,r[6]=c>>>16&255,r[7]=c>>>24&255,r[8]=w>>>0&255,r[9]=w>>>8&255,r[10]=w>>>16&255,r[11]=w>>>24&255,r[12]=A>>>0&255,r[13]=A>>>8&255,r[14]=A>>>16&255,r[15]=A>>>24&255,r[16]=u>>>0&255,r[17]=u>>>8&255,r[18]=u>>>16&255,r[19]=u>>>24&255,r[20]=y>>>0&255,r[21]=y>>>8&255,r[22]=y>>>16&255,r[23]=y>>>24&255,r[24]=l>>>0&255,r[25]=l>>>8&255,r[26]=l>>>16&255,r[27]=l>>>24&255,r[28]=p>>>0&255,r[29]=p>>>8&255,r[30]=p>>>16&255,r[31]=p>>>24&255}(r,t,e,n)}var A=new Uint8Array([101,120,112,97,110,100,32,51,50,45,98,121,116,101,32,107]);function U(r,t,e,n,o,i,a){var h,s,f=new Uint8Array(16),c=new Uint8Array(64);for(s=0;s<16;s++)f[s]=0;for(s=0;s<8;s++)f[s]=i[s];for(;o>=64;){for(g(c,f,a,A),s=0;s<64;s++)r[t+s]=e[n+s]^c[s];for(h=1,s=8;s<16;s++)h=h+(255&f[s])|0,f[s]=255&h,h>>>=8;o-=64,t+=64,n+=64}if(o>0)for(g(c,f,a,A),s=0;s<o;s++)r[t+s]=e[n+s]^c[s];return 0}function x(r,t,e,n,o){var i,a,h=new Uint8Array(16),s=new Uint8Array(64);for(a=0;a<16;a++)h[a]=0;for(a=0;a<8;a++)h[a]=n[a];for(;e>=64;){for(g(s,h,o,A),a=0;a<64;a++)r[t+a]=s[a];for(i=1,a=8;a<16;a++)i=i+(255&h[a])|0,h[a]=255&i,i>>>=8;e-=64,t+=64}if(e>0)for(g(s,h,o,A),a=0;a<e;a++)r[t+a]=s[a];return 0}function _(r,t,e,n,o){var i=new Uint8Array(32);v(i,n,o,A);for(var a=new Uint8Array(8),h=0;h<8;h++)a[h]=n[h+16];return x(r,t,e,a,i)}function E(r,t,e,n,o,i,a){var h=new Uint8Array(32);v(h,i,a,A);for(var s=new Uint8Array(8),f=0;f<8;f++)s[f]=i[f+16];return U(r,t,e,n,o,s,h)}var m=function(r){var t,e,n,o,i,a,h,s;this.buffer=new Uint8Array(16),this.r=new Uint16Array(10),this.h=new Uint16Array(10),this.pad=new Uint16Array(8),this.leftover=0,this.fin=0,t=255&r[0]|(255&r[1])<<8,this.r[0]=8191&t,e=255&r[2]|(255&r[3])<<8,this.r[1]=8191&(t>>>13|e<<3),n=255&r[4]|(255&r[5])<<8,this.r[2]=7939&(e>>>10|n<<6),o=255&r[6]|(255&r[7])<<8,this.r[3]=8191&(n>>>7|o<<9),i=255&r[8]|(255&r[9])<<8,this.r[4]=255&(o>>>4|i<<12),this.r[5]=i>>>1&8190,a=255&r[10]|(255&r[11])<<8,this.r[6]=8191&(i>>>14|a<<2),h=255&r[12]|(255&r[13])<<8,this.r[7]=8065&(a>>>11|h<<5),s=255&r[14]|(255&r[15])<<8,this.r[8]=8191&(h>>>8|s<<8),this.r[9]=s>>>5&127,this.pad[0]=255&r[16]|(255&r[17])<<8,this.pad[1]=255&r[18]|(255&r[19])<<8,this.pad[2]=255&r[20]|(255&r[21])<<8,this.pad[3]=255&r[22]|(255&r[23])<<8,this.pad[4]=255&r[24]|(255&r[25])<<8,this.pad[5]=255&r[26]|(255&r[27])<<8,this.pad[6]=255&r[28]|(255&r[29])<<8,this.pad[7]=255&r[30]|(255&r[31])<<8};function K(r,t,e,n,o,i){var a=new m(i);return a.update(e,n,o),a.finish(r,t),0}function B(r,t,e,n,o,i){var a=new Uint8Array(16);return K(a,0,e,n,o,i),b(r,t,a,0)}function M(r,t,e,n,o){var i;if(e<32)return-1;for(E(r,0,t,0,e,n,o),K(r,16,r,32,e-32,r),i=0;i<16;i++)r[i]=0;return 0}function S(r,t,e,n,o){var i,a=new Uint8Array(32);if(e<32)return-1;if(_(a,0,32,n,o),0!==B(t,16,t,32,e-32,a))return-1;for(E(r,0,t,0,e,n,o),i=0;i<32;i++)r[i]=0;return 0}function T(r,t){var e;for(e=0;e<16;e++)r[e]=0|t[e]}function k(r){var t,e,n=1;for(t=0;t<16;t++)e=r[t]+n+65535,n=Math.floor(e/65536),r[t]=e-65536*n;r[0]+=n-1+37*(n-1)}function L(r,t,e){for(var n,o=~(e-1),i=0;i<16;i++)n=o&(r[i]^t[i]),r[i]^=n,t[i]^=n}function Y(r,t){var n,o,i,a=e(),h=e();for(n=0;n<16;n++)h[n]=t[n];for(k(h),k(h),k(h),o=0;o<2;o++){for(a[0]=h[0]-65517,n=1;n<15;n++)a[n]=h[n]-65535-(a[n-1]>>16&1),a[n-1]&=65535;a[15]=h[15]-32767-(a[14]>>16&1),i=a[15]>>16&1,a[14]&=65535,L(h,a,1-i)}for(n=0;n<16;n++)r[2*n]=255&h[n],r[2*n+1]=h[n]>>8}function P(r,t){var e=new Uint8Array(32),n=new Uint8Array(32);return Y(e,r),Y(n,t),d(e,0,n,0)}function z(r){var t=new Uint8Array(32);return Y(t,r),1&t[0]}function C(r,t){var e;for(e=0;e<16;e++)r[e]=t[2*e]+(t[2*e+1]<<8);r[15]&=32767}function R(r,t,e){for(var n=0;n<16;n++)r[n]=t[n]+e[n]}function F(r,t,e){for(var n=0;n<16;n++)r[n]=t[n]-e[n]}function N(r,t,e){var n,o,i=0,a=0,h=0,s=0,f=0,c=0,u=0,y=0,l=0,p=0,w=0,b=0,d=0,g=0,v=0,A=0,U=0,x=0,_=0,E=0,m=0,K=0,B=0,M=0,S=0,T=0,k=0,L=0,Y=0,P=0,z=0,C=e[0],R=e[1],F=e[2],N=e[3],O=e[4],I=e[5],Z=e[6],H=e[7],D=e[8],G=e[9],j=e[10],J=e[11],V=e[12],X=e[13],$=e[14],q=e[15];i+=(n=t[0])*C,a+=n*R,h+=n*F,s+=n*N,f+=n*O,c+=n*I,u+=n*Z,y+=n*H,l+=n*D,p+=n*G,w+=n*j,b+=n*J,d+=n*V,g+=n*X,v+=n*$,A+=n*q,a+=(n=t[1])*C,h+=n*R,s+=n*F,f+=n*N,c+=n*O,u+=n*I,y+=n*Z,l+=n*H,p+=n*D,w+=n*G,b+=n*j,d+=n*J,g+=n*V,v+=n*X,A+=n*$,U+=n*q,h+=(n=t[2])*C,s+=n*R,f+=n*F,c+=n*N,u+=n*O,y+=n*I,l+=n*Z,p+=n*H,w+=n*D,b+=n*G,d+=n*j,g+=n*J,v+=n*V,A+=n*X,U+=n*$,x+=n*q,s+=(n=t[3])*C,f+=n*R,c+=n*F,u+=n*N,y+=n*O,l+=n*I,p+=n*Z,w+=n*H,b+=n*D,d+=n*G,g+=n*j,v+=n*J,A+=n*V,U+=n*X,x+=n*$,_+=n*q,f+=(n=t[4])*C,c+=n*R,u+=n*F,y+=n*N,l+=n*O,p+=n*I,w+=n*Z,b+=n*H,d+=n*D,g+=n*G,v+=n*j,A+=n*J,U+=n*V,x+=n*X,_+=n*$,E+=n*q,c+=(n=t[5])*C,u+=n*R,y+=n*F,l+=n*N,p+=n*O,w+=n*I,b+=n*Z,d+=n*H,g+=n*D,v+=n*G,A+=n*j,U+=n*J,x+=n*V,_+=n*X,E+=n*$,m+=n*q,u+=(n=t[6])*C,y+=n*R,l+=n*F,p+=n*N,w+=n*O,b+=n*I,d+=n*Z,g+=n*H,v+=n*D,A+=n*G,U+=n*j,x+=n*J,_+=n*V,E+=n*X,m+=n*$,K+=n*q,y+=(n=t[7])*C,l+=n*R,p+=n*F,w+=n*N,b+=n*O,d+=n*I,g+=n*Z,v+=n*H,A+=n*D,U+=n*G,x+=n*j,_+=n*J,E+=n*V,m+=n*X,K+=n*$,B+=n*q,l+=(n=t[8])*C,p+=n*R,w+=n*F,b+=n*N,d+=n*O,g+=n*I,v+=n*Z,A+=n*H,U+=n*D,x+=n*G,_+=n*j,E+=n*J,m+=n*V,K+=n*X,B+=n*$,M+=n*q,p+=(n=t[9])*C,w+=n*R,b+=n*F,d+=n*N,g+=n*O,v+=n*I,A+=n*Z,U+=n*H,x+=n*D,_+=n*G,E+=n*j,m+=n*J,K+=n*V,B+=n*X,M+=n*$,S+=n*q,w+=(n=t[10])*C,b+=n*R,d+=n*F,g+=n*N,v+=n*O,A+=n*I,U+=n*Z,x+=n*H,_+=n*D,E+=n*G,m+=n*j,K+=n*J,B+=n*V,M+=n*X,S+=n*$,T+=n*q,b+=(n=t[11])*C,d+=n*R,g+=n*F,v+=n*N,A+=n*O,U+=n*I,x+=n*Z,_+=n*H,E+=n*D,m+=n*G,K+=n*j,B+=n*J,M+=n*V,S+=n*X,T+=n*$,k+=n*q,d+=(n=t[12])*C,g+=n*R,v+=n*F,A+=n*N,U+=n*O,x+=n*I,_+=n*Z,E+=n*H,m+=n*D,K+=n*G,B+=n*j,M+=n*J,S+=n*V,T+=n*X,k+=n*$,L+=n*q,g+=(n=t[13])*C,v+=n*R,A+=n*F,U+=n*N,x+=n*O,_+=n*I,E+=n*Z,m+=n*H,K+=n*D,B+=n*G,M+=n*j,S+=n*J,T+=n*V,k+=n*X,L+=n*$,Y+=n*q,v+=(n=t[14])*C,A+=n*R,U+=n*F,x+=n*N,_+=n*O,E+=n*I,m+=n*Z,K+=n*H,B+=n*D,M+=n*G,S+=n*j,T+=n*J,k+=n*V,L+=n*X,Y+=n*$,P+=n*q,A+=(n=t[15])*C,a+=38*(x+=n*F),h+=38*(_+=n*N),s+=38*(E+=n*O),f+=38*(m+=n*I),c+=38*(K+=n*Z),u+=38*(B+=n*H),y+=38*(M+=n*D),l+=38*(S+=n*G),p+=38*(T+=n*j),w+=38*(k+=n*J),b+=38*(L+=n*V),d+=38*(Y+=n*X),g+=38*(P+=n*$),v+=38*(z+=n*q),i=(n=(i+=38*(U+=n*R))+(o=1)+65535)-65536*(o=Math.floor(n/65536)),a=(n=a+o+65535)-65536*(o=Math.floor(n/65536)),h=(n=h+o+65535)-65536*(o=Math.floor(n/65536)),s=(n=s+o+65535)-65536*(o=Math.floor(n/65536)),f=(n=f+o+65535)-65536*(o=Math.floor(n/65536)),c=(n=c+o+65535)-65536*(o=Math.floor(n/65536)),u=(n=u+o+65535)-65536*(o=Math.floor(n/65536)),y=(n=y+o+65535)-65536*(o=Math.floor(n/65536)),l=(n=l+o+65535)-65536*(o=Math.floor(n/65536)),p=(n=p+o+65535)-65536*(o=Math.floor(n/65536)),w=(n=w+o+65535)-65536*(o=Math.floor(n/65536)),b=(n=b+o+65535)-65536*(o=Math.floor(n/65536)),d=(n=d+o+65535)-65536*(o=Math.floor(n/65536)),g=(n=g+o+65535)-65536*(o=Math.floor(n/65536)),v=(n=v+o+65535)-65536*(o=Math.floor(n/65536)),A=(n=A+o+65535)-65536*(o=Math.floor(n/65536)),i=(n=(i+=o-1+37*(o-1))+(o=1)+65535)-65536*(o=Math.floor(n/65536)),a=(n=a+o+65535)-65536*(o=Math.floor(n/65536)),h=(n=h+o+65535)-65536*(o=Math.floor(n/65536)),s=(n=s+o+65535)-65536*(o=Math.floor(n/65536)),f=(n=f+o+65535)-65536*(o=Math.floor(n/65536)),c=(n=c+o+65535)-65536*(o=Math.floor(n/65536)),u=(n=u+o+65535)-65536*(o=Math.floor(n/65536)),y=(n=y+o+65535)-65536*(o=Math.floor(n/65536)),l=(n=l+o+65535)-65536*(o=Math.floor(n/65536)),p=(n=p+o+65535)-65536*(o=Math.floor(n/65536)),w=(n=w+o+65535)-65536*(o=Math.floor(n/65536)),b=(n=b+o+65535)-65536*(o=Math.floor(n/65536)),d=(n=d+o+65535)-65536*(o=Math.floor(n/65536)),g=(n=g+o+65535)-65536*(o=Math.floor(n/65536)),v=(n=v+o+65535)-65536*(o=Math.floor(n/65536)),A=(n=A+o+65535)-65536*(o=Math.floor(n/65536)),i+=o-1+37*(o-1),r[0]=i,r[1]=a,r[2]=h,r[3]=s,r[4]=f,r[5]=c,r[6]=u,r[7]=y,r[8]=l,r[9]=p,r[10]=w,r[11]=b,r[12]=d,r[13]=g,r[14]=v,r[15]=A}function O(r,t){N(r,t,t)}function I(r,t){var n,o=e();for(n=0;n<16;n++)o[n]=t[n];for(n=253;n>=0;n--)O(o,o),2!==n&&4!==n&&N(o,o,t);for(n=0;n<16;n++)r[n]=o[n]}function Z(r,t){var n,o=e();for(n=0;n<16;n++)o[n]=t[n];for(n=250;n>=0;n--)O(o,o),1!==n&&N(o,o,t);for(n=0;n<16;n++)r[n]=o[n]}function H(r,t,n){var o,i,a=new Uint8Array(32),h=new Float64Array(80),f=e(),c=e(),u=e(),y=e(),l=e(),p=e();for(i=0;i<31;i++)a[i]=t[i];for(a[31]=127&t[31]|64,a[0]&=248,C(h,n),i=0;i<16;i++)c[i]=h[i],y[i]=f[i]=u[i]=0;for(f[0]=y[0]=1,i=254;i>=0;--i)L(f,c,o=a[i>>>3]>>>(7&i)&1),L(u,y,o),R(l,f,u),F(f,f,u),R(u,c,y),F(c,c,y),O(y,l),O(p,f),N(f,u,f),N(u,c,l),R(l,f,u),F(f,f,u),O(c,f),F(u,y,p),N(f,u,s),R(f,f,y),N(u,u,f),N(f,y,p),N(y,c,h),O(c,l),L(f,c,o),L(u,y,o);for(i=0;i<16;i++)h[i+16]=f[i],h[i+32]=u[i],h[i+48]=c[i],h[i+64]=y[i];var w=h.subarray(32),b=h.subarray(16);return I(w,w),N(b,b,w),Y(r,b),0}function D(r,t){return H(r,t,i)}function G(r,t){return n(t,32),D(r,t)}function j(r,t,e){var n=new Uint8Array(32);return H(n,e,t),v(r,o,n,A)}m.prototype.blocks=function(r,t,e){for(var n,o,i,a,h,s,f,c,u,y,l,p,w,b,d,g,v,A,U,x=this.fin?0:2048,_=this.h[0],E=this.h[1],m=this.h[2],K=this.h[3],B=this.h[4],M=this.h[5],S=this.h[6],T=this.h[7],k=this.h[8],L=this.h[9],Y=this.r[0],P=this.r[1],z=this.r[2],C=this.r[3],R=this.r[4],F=this.r[5],N=this.r[6],O=this.r[7],I=this.r[8],Z=this.r[9];e>=16;)y=u=0,y+=(_+=8191&(n=255&r[t+0]|(255&r[t+1])<<8))*Y,y+=(E+=8191&(n>>>13|(o=255&r[t+2]|(255&r[t+3])<<8)<<3))*(5*Z),y+=(m+=8191&(o>>>10|(i=255&r[t+4]|(255&r[t+5])<<8)<<6))*(5*I),y+=(K+=8191&(i>>>7|(a=255&r[t+6]|(255&r[t+7])<<8)<<9))*(5*O),u=(y+=(B+=8191&(a>>>4|(h=255&r[t+8]|(255&r[t+9])<<8)<<12))*(5*N))>>>13,y&=8191,y+=(M+=h>>>1&8191)*(5*F),y+=(S+=8191&(h>>>14|(s=255&r[t+10]|(255&r[t+11])<<8)<<2))*(5*R),y+=(T+=8191&(s>>>11|(f=255&r[t+12]|(255&r[t+13])<<8)<<5))*(5*C),y+=(k+=8191&(f>>>8|(c=255&r[t+14]|(255&r[t+15])<<8)<<8))*(5*z),l=u+=(y+=(L+=c>>>5|x)*(5*P))>>>13,l+=_*P,l+=E*Y,l+=m*(5*Z),l+=K*(5*I),u=(l+=B*(5*O))>>>13,l&=8191,l+=M*(5*N),l+=S*(5*F),l+=T*(5*R),l+=k*(5*C),u+=(l+=L*(5*z))>>>13,l&=8191,p=u,p+=_*z,p+=E*P,p+=m*Y,p+=K*(5*Z),u=(p+=B*(5*I))>>>13,p&=8191,p+=M*(5*O),p+=S*(5*N),p+=T*(5*F),p+=k*(5*R),w=u+=(p+=L*(5*C))>>>13,w+=_*C,w+=E*z,w+=m*P,w+=K*Y,u=(w+=B*(5*Z))>>>13,w&=8191,w+=M*(5*I),w+=S*(5*O),w+=T*(5*N),w+=k*(5*F),b=u+=(w+=L*(5*R))>>>13,b+=_*R,b+=E*C,b+=m*z,b+=K*P,u=(b+=B*Y)>>>13,b&=8191,b+=M*(5*Z),b+=S*(5*I),b+=T*(5*O),b+=k*(5*N),d=u+=(b+=L*(5*F))>>>13,d+=_*F,d+=E*R,d+=m*C,d+=K*z,u=(d+=B*P)>>>13,d&=8191,d+=M*Y,d+=S*(5*Z),d+=T*(5*I),d+=k*(5*O),g=u+=(d+=L*(5*N))>>>13,g+=_*N,g+=E*F,g+=m*R,g+=K*C,u=(g+=B*z)>>>13,g&=8191,g+=M*P,g+=S*Y,g+=T*(5*Z),g+=k*(5*I),v=u+=(g+=L*(5*O))>>>13,v+=_*O,v+=E*N,v+=m*F,v+=K*R,u=(v+=B*C)>>>13,v&=8191,v+=M*z,v+=S*P,v+=T*Y,v+=k*(5*Z),A=u+=(v+=L*(5*I))>>>13,A+=_*I,A+=E*O,A+=m*N,A+=K*F,u=(A+=B*R)>>>13,A&=8191,A+=M*C,A+=S*z,A+=T*P,A+=k*Y,U=u+=(A+=L*(5*Z))>>>13,U+=_*Z,U+=E*I,U+=m*O,U+=K*N,u=(U+=B*F)>>>13,U&=8191,U+=M*R,U+=S*C,U+=T*z,U+=k*P,_=y=8191&(u=(u=((u+=(U+=L*Y)>>>13)<<2)+u|0)+(y&=8191)|0),E=l+=u>>>=13,m=p&=8191,K=w&=8191,B=b&=8191,M=d&=8191,S=g&=8191,T=v&=8191,k=A&=8191,L=U&=8191,t+=16,e-=16;this.h[0]=_,this.h[1]=E,this.h[2]=m,this.h[3]=K,this.h[4]=B,this.h[5]=M,this.h[6]=S,this.h[7]=T,this.h[8]=k,this.h[9]=L},m.prototype.finish=function(r,t){var e,n,o,i,a=new Uint16Array(10);if(this.leftover){for(i=this.leftover,this.buffer[i++]=1;i<16;i++)this.buffer[i]=0;this.fin=1,this.blocks(this.buffer,0,16)}for(e=this.h[1]>>>13,this.h[1]&=8191,i=2;i<10;i++)this.h[i]+=e,e=this.h[i]>>>13,this.h[i]&=8191;for(this.h[0]+=5*e,e=this.h[0]>>>13,this.h[0]&=8191,this.h[1]+=e,e=this.h[1]>>>13,this.h[1]&=8191,this.h[2]+=e,a[0]=this.h[0]+5,e=a[0]>>>13,a[0]&=8191,i=1;i<10;i++)a[i]=this.h[i]+e,e=a[i]>>>13,a[i]&=8191;for(a[9]-=8192,n=(1^e)-1,i=0;i<10;i++)a[i]&=n;for(n=~n,i=0;i<10;i++)this.h[i]=this.h[i]&n|a[i];for(this.h[0]=65535&(this.h[0]|this.h[1]<<13),this.h[1]=65535&(this.h[1]>>>3|this.h[2]<<10),this.h[2]=65535&(this.h[2]>>>6|this.h[3]<<7),this.h[3]=65535&(this.h[3]>>>9|this.h[4]<<4),this.h[4]=65535&(this.h[4]>>>12|this.h[5]<<1|this.h[6]<<14),this.h[5]=65535&(this.h[6]>>>2|this.h[7]<<11),this.h[6]=65535&(this.h[7]>>>5|this.h[8]<<8),this.h[7]=65535&(this.h[8]>>>8|this.h[9]<<5),o=this.h[0]+this.pad[0],this.h[0]=65535&o,i=1;i<8;i++)o=(this.h[i]+this.pad[i]|0)+(o>>>16)|0,this.h[i]=65535&o;r[t+0]=this.h[0]>>>0&255,r[t+1]=this.h[0]>>>8&255,r[t+2]=this.h[1]>>>0&255,r[t+3]=this.h[1]>>>8&255,r[t+4]=this.h[2]>>>0&255,r[t+5]=this.h[2]>>>8&255,r[t+6]=this.h[3]>>>0&255,r[t+7]=this.h[3]>>>8&255,r[t+8]=this.h[4]>>>0&255,r[t+9]=this.h[4]>>>8&255,r[t+10]=this.h[5]>>>0&255,r[t+11]=this.h[5]>>>8&255,r[t+12]=this.h[6]>>>0&255,r[t+13]=this.h[6]>>>8&255,r[t+14]=this.h[7]>>>0&255,r[t+15]=this.h[7]>>>8&255},m.prototype.update=function(r,t,e){var n,o;if(this.leftover){for((o=16-this.leftover)>e&&(o=e),n=0;n<o;n++)this.buffer[this.leftover+n]=r[t+n];if(e-=o,t+=o,this.leftover+=o,this.leftover<16)return;this.blocks(this.buffer,0,16),this.leftover=0}if(e>=16&&(o=e-e%16,this.blocks(r,t,o),t+=o,e-=o),e){for(n=0;n<e;n++)this.buffer[this.leftover+n]=r[t+n];this.leftover+=e}};var J=M,V=S,X=[1116352408,3609767458,1899447441,602891725,3049323471,3964484399,3921009573,2173295548,961987163,4081628472,1508970993,3053834265,2453635748,2937671579,2870763221,3664609560,3624381080,2734883394,310598401,1164996542,607225278,1323610764,1426881987,3590304994,1925078388,4068182383,2162078206,991336113,2614888103,633803317,3248222580,3479774868,3835390401,2666613458,4022224774,944711139,264347078,2341262773,604807628,2007800933,770255983,1495990901,1249150122,1856431235,1555081692,3175218132,1996064986,2198950837,2554220882,3999719339,2821834349,766784016,2952996808,2566594879,3210313671,3203337956,3336571891,1034457026,3584528711,2466948901,113926993,3758326383,338241895,168717936,666307205,1188179964,773529912,1546045734,1294757372,1522805485,1396182291,2643833823,1695183700,2343527390,1986661051,1014477480,2177026350,1206759142,2456956037,344077627,2730485921,1290863460,2820302411,3158454273,3259730800,3505952657,3345764771,106217008,3516065817,3606008344,3600352804,1432725776,4094571909,1467031594,275423344,851169720,430227734,3100823752,506948616,1363258195,659060556,3750685593,883997877,3785050280,958139571,3318307427,1322822218,3812723403,1537002063,2003034995,1747873779,3602036899,1955562222,1575990012,2024104815,1125592928,2227730452,2716904306,2361852424,442776044,2428436474,593698344,2756734187,3733110249,3204031479,2999351573,3329325298,3815920427,3391569614,3928383900,3515267271,566280711,3940187606,3454069534,4118630271,4000239992,116418474,1914138554,174292421,2731055270,289380356,3203993006,460393269,320620315,685471733,587496836,852142971,1086792851,1017036298,365543100,1126000580,2618297676,1288033470,3409855158,1501505948,4234509866,1607167915,987167468,1816402316,1246189591];function $(r,t,e,n){for(var o,i,a,h,s,f,c,u,y,l,p,w,b,d,g,v,A,U,x,_,E,m,K,B,M,S,T=new Int32Array(16),k=new Int32Array(16),L=r[0],Y=r[1],P=r[2],z=r[3],C=r[4],R=r[5],F=r[6],N=r[7],O=t[0],I=t[1],Z=t[2],H=t[3],D=t[4],G=t[5],j=t[6],J=t[7],V=0;n>=128;){for(x=0;x<16;x++)_=8*x+V,T[x]=e[_+0]<<24|e[_+1]<<16|e[_+2]<<8|e[_+3],k[x]=e[_+4]<<24|e[_+5]<<16|e[_+6]<<8|e[_+7];for(x=0;x<80;x++)if(o=L,i=Y,a=P,h=z,s=C,f=R,c=F,y=O,l=I,p=Z,w=H,b=D,d=G,g=j,K=65535&(m=J),B=m>>>16,M=65535&(E=N),S=E>>>16,K+=65535&(m=(D>>>14|C<<18)^(D>>>18|C<<14)^(C>>>9|D<<23)),B+=m>>>16,M+=65535&(E=(C>>>14|D<<18)^(C>>>18|D<<14)^(D>>>9|C<<23)),S+=E>>>16,K+=65535&(m=D&G^~D&j),B+=m>>>16,M+=65535&(E=C&R^~C&F),S+=E>>>16,K+=65535&(m=X[2*x+1]),B+=m>>>16,M+=65535&(E=X[2*x]),S+=E>>>16,E=T[x%16],B+=(m=k[x%16])>>>16,M+=65535&E,S+=E>>>16,M+=(B+=(K+=65535&m)>>>16)>>>16,K=65535&(m=U=65535&K|B<<16),B=m>>>16,M=65535&(E=A=65535&M|(S+=M>>>16)<<16),S=E>>>16,K+=65535&(m=(O>>>28|L<<4)^(L>>>2|O<<30)^(L>>>7|O<<25)),B+=m>>>16,M+=65535&(E=(L>>>28|O<<4)^(O>>>2|L<<30)^(O>>>7|L<<25)),S+=E>>>16,B+=(m=O&I^O&Z^I&Z)>>>16,M+=65535&(E=L&Y^L&P^Y&P),S+=E>>>16,u=65535&(M+=(B+=(K+=65535&m)>>>16)>>>16)|(S+=M>>>16)<<16,v=65535&K|B<<16,K=65535&(m=w),B=m>>>16,M=65535&(E=h),S=E>>>16,B+=(m=U)>>>16,M+=65535&(E=A),S+=E>>>16,Y=o,P=i,z=a,C=h=65535&(M+=(B+=(K+=65535&m)>>>16)>>>16)|(S+=M>>>16)<<16,R=s,F=f,N=c,L=u,I=y,Z=l,H=p,D=w=65535&K|B<<16,G=b,j=d,J=g,O=v,x%16==15)for(_=0;_<16;_++)E=T[_],K=65535&(m=k[_]),B=m>>>16,M=65535&E,S=E>>>16,E=T[(_+9)%16],K+=65535&(m=k[(_+9)%16]),B+=m>>>16,M+=65535&E,S+=E>>>16,A=T[(_+1)%16],K+=65535&(m=((U=k[(_+1)%16])>>>1|A<<31)^(U>>>8|A<<24)^(U>>>7|A<<25)),B+=m>>>16,M+=65535&(E=(A>>>1|U<<31)^(A>>>8|U<<24)^A>>>7),S+=E>>>16,A=T[(_+14)%16],B+=(m=((U=k[(_+14)%16])>>>19|A<<13)^(A>>>29|U<<3)^(U>>>6|A<<26))>>>16,M+=65535&(E=(A>>>19|U<<13)^(U>>>29|A<<3)^A>>>6),S+=E>>>16,S+=(M+=(B+=(K+=65535&m)>>>16)>>>16)>>>16,T[_]=65535&M|S<<16,k[_]=65535&K|B<<16;K=65535&(m=O),B=m>>>16,M=65535&(E=L),S=E>>>16,E=r[0],B+=(m=t[0])>>>16,M+=65535&E,S+=E>>>16,S+=(M+=(B+=(K+=65535&m)>>>16)>>>16)>>>16,r[0]=L=65535&M|S<<16,t[0]=O=65535&K|B<<16,K=65535&(m=I),B=m>>>16,M=65535&(E=Y),S=E>>>16,E=r[1],B+=(m=t[1])>>>16,M+=65535&E,S+=E>>>16,S+=(M+=(B+=(K+=65535&m)>>>16)>>>16)>>>16,r[1]=Y=65535&M|S<<16,t[1]=I=65535&K|B<<16,K=65535&(m=Z),B=m>>>16,M=65535&(E=P),S=E>>>16,E=r[2],B+=(m=t[2])>>>16,M+=65535&E,S+=E>>>16,S+=(M+=(B+=(K+=65535&m)>>>16)>>>16)>>>16,r[2]=P=65535&M|S<<16,t[2]=Z=65535&K|B<<16,K=65535&(m=H),B=m>>>16,M=65535&(E=z),S=E>>>16,E=r[3],B+=(m=t[3])>>>16,M+=65535&E,S+=E>>>16,S+=(M+=(B+=(K+=65535&m)>>>16)>>>16)>>>16,r[3]=z=65535&M|S<<16,t[3]=H=65535&K|B<<16,K=65535&(m=D),B=m>>>16,M=65535&(E=C),S=E>>>16,E=r[4],B+=(m=t[4])>>>16,M+=65535&E,S+=E>>>16,S+=(M+=(B+=(K+=65535&m)>>>16)>>>16)>>>16,r[4]=C=65535&M|S<<16,t[4]=D=65535&K|B<<16,K=65535&(m=G),B=m>>>16,M=65535&(E=R),S=E>>>16,E=r[5],B+=(m=t[5])>>>16,M+=65535&E,S+=E>>>16,S+=(M+=(B+=(K+=65535&m)>>>16)>>>16)>>>16,r[5]=R=65535&M|S<<16,t[5]=G=65535&K|B<<16,K=65535&(m=j),B=m>>>16,M=65535&(E=F),S=E>>>16,E=r[6],B+=(m=t[6])>>>16,M+=65535&E,S+=E>>>16,S+=(M+=(B+=(K+=65535&m)>>>16)>>>16)>>>16,r[6]=F=65535&M|S<<16,t[6]=j=65535&K|B<<16,K=65535&(m=J),B=m>>>16,M=65535&(E=N),S=E>>>16,E=r[7],B+=(m=t[7])>>>16,M+=65535&E,S+=E>>>16,S+=(M+=(B+=(K+=65535&m)>>>16)>>>16)>>>16,r[7]=N=65535&M|S<<16,t[7]=J=65535&K|B<<16,V+=128,n-=128}return n}function q(r,t,e){var n,o=new Int32Array(8),i=new Int32Array(8),a=new Uint8Array(256),h=e;for(o[0]=1779033703,o[1]=3144134277,o[2]=1013904242,o[3]=2773480762,o[4]=1359893119,o[5]=2600822924,o[6]=528734635,o[7]=1541459225,i[0]=4089235720,i[1]=2227873595,i[2]=4271175723,i[3]=1595750129,i[4]=2917565137,i[5]=725511199,i[6]=4215389547,i[7]=327033209,$(o,i,t,e),e%=128,n=0;n<e;n++)a[n]=t[h-e+n];for(a[e]=128,a[(e=256-128*(e<112?1:0))-9]=0,p(a,e-8,h/536870912|0,h<<3),$(o,i,a,e),n=0;n<8;n++)p(r,8*n,o[n],i[n]);return 0}function Q(r,t){var n=e(),o=e(),i=e(),a=e(),h=e(),s=e(),f=e(),u=e(),y=e();F(n,r[1],r[0]),F(y,t[1],t[0]),N(n,n,y),R(o,r[0],r[1]),R(y,t[0],t[1]),N(o,o,y),N(i,r[3],t[3]),N(i,i,c),N(a,r[2],t[2]),R(a,a,a),F(h,o,n),F(s,a,i),R(f,a,i),R(u,o,n),N(r[0],h,s),N(r[1],u,f),N(r[2],f,s),N(r[3],h,u)}function W(r,t,e){var n;for(n=0;n<4;n++)L(r[n],t[n],e)}function rr(r,t){var n=e(),o=e(),i=e();I(i,t[2]),N(n,t[0],i),N(o,t[1],i),Y(r,o),r[31]^=z(n)<<7}function tr(r,t,e){var n,o;for(T(r[0],a),T(r[1],h),T(r[2],h),T(r[3],a),o=255;o>=0;--o)W(r,t,n=e[o/8|0]>>(7&o)&1),Q(t,r),Q(r,r),W(r,t,n)}function er(r,t){var n=[e(),e(),e(),e()];T(n[0],u),T(n[1],y),T(n[2],h),N(n[3],u,y),tr(r,n,t)}function nr(r,t,o){var i,a=new Uint8Array(64),h=[e(),e(),e(),e()];for(o||n(t,32),q(a,t,32),a[0]&=248,a[31]&=127,a[31]|=64,er(h,a),rr(r,h),i=0;i<32;i++)t[i+32]=r[i];return 0}var or=new Float64Array([237,211,245,92,26,99,18,88,214,156,247,162,222,249,222,20,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,16]);function ir(r,t){var e,n,o,i;for(n=63;n>=32;--n){for(e=0,o=n-32,i=n-12;o<i;++o)t[o]+=e-16*t[n]*or[o-(n-32)],e=Math.floor((t[o]+128)/256),t[o]-=256*e;t[o]+=e,t[n]=0}for(e=0,o=0;o<32;o++)t[o]+=e-(t[31]>>4)*or[o],e=t[o]>>8,t[o]&=255;for(o=0;o<32;o++)t[o]-=e*or[o];for(n=0;n<32;n++)t[n+1]+=t[n]>>8,r[n]=255&t[n]}function ar(r){var t,e=new Float64Array(64);for(t=0;t<64;t++)e[t]=r[t];for(t=0;t<64;t++)r[t]=0;ir(r,e)}function hr(r,t,n,o){var i,a,h=new Uint8Array(64),s=new Uint8Array(64),f=new Uint8Array(64),c=new Float64Array(64),u=[e(),e(),e(),e()];q(h,o,32),h[0]&=248,h[31]&=127,h[31]|=64;var y=n+64;for(i=0;i<n;i++)r[64+i]=t[i];for(i=0;i<32;i++)r[32+i]=h[32+i];for(q(f,r.subarray(32),n+32),ar(f),er(u,f),rr(r,u),i=32;i<64;i++)r[i]=o[i];for(q(s,r,n+64),ar(s),i=0;i<64;i++)c[i]=0;for(i=0;i<32;i++)c[i]=f[i];for(i=0;i<32;i++)for(a=0;a<32;a++)c[i+a]+=s[i]*h[a];return ir(r.subarray(32),c),y}function sr(r,t,n,o){var i,s=new Uint8Array(32),c=new Uint8Array(64),u=[e(),e(),e(),e()],y=[e(),e(),e(),e()];if(n<64)return-1;if(function(r,t){var n=e(),o=e(),i=e(),s=e(),c=e(),u=e(),y=e();return T(r[2],h),C(r[1],t),O(i,r[1]),N(s,i,f),F(i,i,r[2]),R(s,r[2],s),O(c,s),O(u,c),N(y,u,c),N(n,y,i),N(n,n,s),Z(n,n),N(n,n,i),N(n,n,s),N(n,n,s),N(r[0],n,s),O(o,r[0]),N(o,o,s),P(o,i)&&N(r[0],r[0],l),O(o,r[0]),N(o,o,s),P(o,i)?-1:(z(r[0])===t[31]>>7&&F(r[0],a,r[0]),N(r[3],r[0],r[1]),0)}(y,o))return-1;for(i=0;i<n;i++)r[i]=t[i];for(i=0;i<32;i++)r[i+32]=o[i];if(q(c,r,n),ar(c),tr(u,y,c),er(y,t.subarray(32)),Q(u,y),rr(s,u),n-=64,d(t,0,s,0)){for(i=0;i<n;i++)r[i]=0;return-1}for(i=0;i<n;i++)r[i]=t[i+64];return n}var fr,cr=16,ur=64,yr=32,lr=64;function pr(r,t){if(32!==r.length)throw new Error("bad key size");if(24!==t.length)throw new Error("bad nonce size")}function wr(){for(var r=0;r<arguments.length;r++)if(!(arguments[r]instanceof Uint8Array))throw new TypeError("unexpected type, use Uint8Array")}function br(r){for(var t=0;t<r.length;t++)r[t]=0}t.lowlevel={crypto_core_hsalsa20:v,crypto_stream_xor:E,crypto_stream:_,crypto_stream_salsa20_xor:U,crypto_stream_salsa20:x,crypto_onetimeauth:K,crypto_onetimeauth_verify:B,crypto_verify_16:b,crypto_verify_32:d,crypto_secretbox:M,crypto_secretbox_open:S,crypto_scalarmult:H,crypto_scalarmult_base:D,crypto_box_beforenm:j,crypto_box_afternm:J,crypto_box:function(r,t,e,n,o,i){var a=new Uint8Array(32);return j(a,o,i),J(r,t,e,n,a)},crypto_box_open:function(r,t,e,n,o,i){var a=new Uint8Array(32);return j(a,o,i),V(r,t,e,n,a)},crypto_box_keypair:G,crypto_hash:q,crypto_sign:hr,crypto_sign_keypair:nr,crypto_sign_open:sr,crypto_secretbox_KEYBYTES:32,crypto_secretbox_NONCEBYTES:24,crypto_secretbox_ZEROBYTES:32,crypto_secretbox_BOXZEROBYTES:cr,crypto_scalarmult_BYTES:32,crypto_scalarmult_SCALARBYTES:32,crypto_box_PUBLICKEYBYTES:32,crypto_box_SECRETKEYBYTES:32,crypto_box_BEFORENMBYTES:32,crypto_box_NONCEBYTES:24,crypto_box_ZEROBYTES:32,crypto_box_BOXZEROBYTES:16,crypto_sign_BYTES:ur,crypto_sign_PUBLICKEYBYTES:yr,crypto_sign_SECRETKEYBYTES:lr,crypto_sign_SEEDBYTES:32,crypto_hash_BYTES:64,gf:e,D:f,L:or,pack25519:Y,unpack25519:C,M:N,A:R,S:O,Z:F,pow2523:Z,add:Q,set25519:T,modL:ir,scalarmult:tr,scalarbase:er},t.randomBytes=function(r){var t=new Uint8Array(r);return n(t,r),t},t.secretbox=function(r,t,e){wr(r,t,e),pr(e,t);for(var n=new Uint8Array(32+r.length),o=new Uint8Array(n.length),i=0;i<r.length;i++)n[i+32]=r[i];return M(o,n,n.length,t,e),o.subarray(cr)},t.secretbox.open=function(r,t,e){wr(r,t,e),pr(e,t);for(var n=new Uint8Array(cr+r.length),o=new Uint8Array(n.length),i=0;i<r.length;i++)n[i+cr]=r[i];return n.length<32||0!==S(o,n,n.length,t,e)?null:o.subarray(32)},t.secretbox.keyLength=32,t.secretbox.nonceLength=24,t.secretbox.overheadLength=cr,t.scalarMult=function(r,t){if(wr(r,t),32!==r.length)throw new Error("bad n size");if(32!==t.length)throw new Error("bad p size");var e=new Uint8Array(32);return H(e,r,t),e},t.scalarMult.base=function(r){if(wr(r),32!==r.length)throw new Error("bad n size");var t=new Uint8Array(32);return D(t,r),t},t.scalarMult.scalarLength=32,t.scalarMult.groupElementLength=32,t.box=function(r,e,n,o){var i=t.box.before(n,o);return t.secretbox(r,e,i)},t.box.before=function(r,t){wr(r,t),function(r,t){if(32!==r.length)throw new Error("bad public key size");if(32!==t.length)throw new Error("bad secret key size")}(r,t);var e=new Uint8Array(32);return j(e,r,t),e},t.box.after=t.secretbox,t.box.open=function(r,e,n,o){var i=t.box.before(n,o);return t.secretbox.open(r,e,i)},t.box.open.after=t.secretbox.open,t.box.keyPair=function(){var r=new Uint8Array(32),t=new Uint8Array(32);return G(r,t),{publicKey:r,secretKey:t}},t.box.keyPair.fromSecretKey=function(r){if(wr(r),32!==r.length)throw new Error("bad secret key size");var t=new Uint8Array(32);return D(t,r),{publicKey:t,secretKey:new Uint8Array(r)}},t.box.publicKeyLength=32,t.box.secretKeyLength=32,t.box.sharedKeyLength=32,t.box.nonceLength=24,t.box.overheadLength=t.secretbox.overheadLength,t.sign=function(r,t){if(wr(r,t),t.length!==lr)throw new Error("bad secret key size");var e=new Uint8Array(ur+r.length);return hr(e,r,r.length,t),e},t.sign.open=function(r,t){if(wr(r,t),t.length!==yr)throw new Error("bad public key size");var e=new Uint8Array(r.length),n=sr(e,r,r.length,t);if(n<0)return null;for(var o=new Uint8Array(n),i=0;i<o.length;i++)o[i]=e[i];return o},t.sign.detached=function(r,e){for(var n=t.sign(r,e),o=new Uint8Array(ur),i=0;i<o.length;i++)o[i]=n[i];return o},t.sign.detached.verify=function(r,t,e){if(wr(r,t,e),t.length!==ur)throw new Error("bad signature size");if(e.length!==yr)throw new Error("bad public key size");var n,o=new Uint8Array(ur+r.length),i=new Uint8Array(ur+r.length);for(n=0;n<ur;n++)o[n]=t[n];for(n=0;n<r.length;n++)o[n+ur]=r[n];return sr(i,o,o.length,e)>=0},t.sign.keyPair=function(){var r=new Uint8Array(yr),t=new Uint8Array(lr);return nr(r,t),{publicKey:r,secretKey:t}},t.sign.keyPair.fromSecretKey=function(r){if(wr(r),r.length!==lr)throw new Error("bad secret key size");for(var t=new Uint8Array(yr),e=0;e<t.length;e++)t[e]=r[32+e];return{publicKey:t,secretKey:new Uint8Array(r)}},t.sign.keyPair.fromSeed=function(r){if(wr(r),32!==r.length)throw new Error("bad seed size");for(var t=new Uint8Array(yr),e=new Uint8Array(lr),n=0;n<32;n++)e[n]=r[n];return nr(t,e,!0),{publicKey:t,secretKey:e}},t.sign.publicKeyLength=yr,t.sign.secretKeyLength=lr,t.sign.seedLength=32,t.sign.signatureLength=ur,t.hash=function(r){wr(r);var t=new Uint8Array(64);return q(t,r,r.length),t},t.hash.hashLength=64,t.verify=function(r,t){return wr(r,t),0!==r.length&&0!==t.length&&r.length===t.length&&0===w(r,0,t,0,r.length)},t.setPRNG=function(r){n=r},(fr="undefined"!=typeof self?self.crypto||self.msCrypto:null)&&fr.getRandomValues?t.setPRNG((function(r,t){var e,n=new Uint8Array(t);for(e=0;e<t;e+=65536)fr.getRandomValues(n.subarray(e,e+Math.min(t-e,65536)));for(e=0;e<t;e++)r[e]=n[e];br(n)})):(fr=r)&&fr.randomBytes&&t.setPRNG((function(r,t){var e,n=fr.randomBytes(t);for(e=0;e<t;e++)r[e]=n[e];br(n)}))}(e.exports?e.exports:self.nacl=self.nacl||{});var n,o,i,a=e.exports,h={exports:{}};o=t,i=function(){var r={};function t(r){if(!/^(?:[A-Za-z0-9+\/]{2}[A-Za-z0-9+\/]{2})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/.test(r))throw new TypeError("invalid encoding")}return r.decodeUTF8=function(r){if("string"!=typeof r)throw new TypeError("expected string");var t,e=unescape(encodeURIComponent(r)),n=new Uint8Array(e.length);for(t=0;t<e.length;t++)n[t]=e.charCodeAt(t);return n},r.encodeUTF8=function(r){var t,e=[];for(t=0;t<r.length;t++)e.push(String.fromCharCode(r[t]));return decodeURIComponent(escape(e.join("")))},"undefined"==typeof atob?void 0!==Buffer.from?(r.encodeBase64=function(r){return Buffer.from(r).toString("base64")},r.decodeBase64=function(r){return t(r),new Uint8Array(Array.prototype.slice.call(Buffer.from(r,"base64"),0))}):(r.encodeBase64=function(r){return new Buffer(r).toString("base64")},r.decodeBase64=function(r){return t(r),new Uint8Array(Array.prototype.slice.call(new Buffer(r,"base64"),0))}):(r.encodeBase64=function(r){var t,e=[],n=r.length;for(t=0;t<n;t++)e.push(String.fromCharCode(r[t]));return btoa(e.join(""))},r.decodeBase64=function(r){t(r);var e,n=atob(r),o=new Uint8Array(n.length);for(e=0;e<n.length;e++)o[e]=n.charCodeAt(e);return o}),r},(n=h).exports?n.exports=i():(o.nacl||(o.nacl={}),o.nacl.util=i());var s=h.exports;const f=a;f.util=s;const c=()=>Math.floor(2147483648*Math.random()).toString(36),u=r=>{if(1==r){const r=f.sign.keyPair();return{signPublicKey:r.publicKey,signSecretKey:r.secretKey,signPublicKeyHex:g(r.publicKey),signSecretKeyHex:g(r.secretKey)}}{const r=f.box.keyPair(),t=g(r.publicKey),e=g(r.secretKey);return{privateKey:r.secretKey,publicKey:r.publicKey,privateKeyHex:e,publicKeyHex:t}}};function y({publicKeyHex:r,publicKey:t},e,n){if("x25519-xsalsa20-poly1305"===n){if("string"!=typeof e.data)throw new Error('Cannot detect secret message, message params should be of the form {data: "secret message"} ');const n=f.box.keyPair();let o;if(t)try{o=f.util.decodeBase64(t)}catch(r){throw new Error("Bad public key")}else{if(!r)throw new Error("No public key");try{o=v(r)}catch(r){throw new Error("Bad public key")}}const i=f.util.decodeUTF8(e.data),a=f.randomBytes(f.box.nonceLength),h=f.box(i,a,o,n.secretKey);return{version:"x25519-xsalsa20-poly1305",nonce:f.util.encodeBase64(a),ephemPublicKey:f.util.encodeBase64(n.publicKey),ciphertext:f.util.encodeBase64(h)}}throw new Error("Encryption type/version not supported")}function l(r,t){if("x25519-xsalsa20-poly1305"===r.version){const e=v(t),n=f.box.keyPair.fromSecretKey(e).secretKey,o=f.util.decodeBase64(r.nonce),i=f.util.decodeBase64(r.ciphertext),a=f.util.decodeBase64(r.ephemPublicKey),h=f.box.open(i,o,a,n);let s;try{s=f.util.encodeUTF8(h)}catch(r){throw new Error("Decryption failed.")}if(s)return s;throw new Error("Decryption failed.")}throw new Error("Encryption type/version not supported.")}const p=(r,t,e="hex")=>{try{const n=f.sign(f.util.decodeUTF8(r),v(t));return"base64"==e?f.util.encodeBase64(n):g(n)}catch(r){console.error(r.message)}},w=(r,t,e="hex")=>{try{const n=f.sign.open("base64"==e?f.util.decodeUTF8(r):v(r),v(t));return f.util.encodeUTF8(n)}catch(r){console.error(r.message)}},b=(r,t,e)=>t.reduce(((r,t)=>w(r,t,e)),r),d=(r,t,e)=>t.reduce(((r,t)=>p(r,t,e)),r);function g(r){return Array.from(new Uint8Array(r)).map((r=>r.toString(16).padStart(2,"0"))).join("")}function v(r){const t=r.match(/.{1,2}(?=(.{2})+(?!.))|.{1,2}$/g);return new Uint8Array(t.map((r=>parseInt(r,16))))}const A=async(r="message",t)=>{const e=y({publicKey:void 0,publicKeyHex:t},{data:r},"x25519-xsalsa20-poly1305");return g(f.util.decodeUTF8(JSON.stringify(e)))},U=async(r,t)=>{const e=v(r),n=JSON.parse(f.util.encodeUTF8(e));let o;try{o=l(n,t)}catch(r){console.error(r)}return o};export{l as _decrypt,y as _encrypt,g as bufferToHex,U as decrypt,A as encrypt,v as hexToBuffer,u as keyPair,f as nacl,c as random,p as sign,d as signMultiple,w as verifySignature,b as verifySignatures};
