package cn.bus.sso.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.commons.lang3.StringUtils;

import java.util.Date;
import java.util.Map;

public class JwtUtil {
    public static String encode(String name, String secret, long timeOut) {
        Algorithm algorithm = Algorithm.HMAC256(secret);
        String token = JWT.create()
                //设置过期时间为一个小时
                .withExpiresAt(new Date(System.currentTimeMillis() + timeOut))
                //设置负载
                .withClaim("name", name).sign(algorithm);
        return token;
    }

    public static Map<String, Claim> decode(String token, String secret) {
        if (StringUtils.isEmpty(token)) {
            System.out.println(token);
        }
        Algorithm algorithm = Algorithm.HMAC256(secret);
        JWTVerifier jwtVerifier = JWT.require(algorithm).build();
        DecodedJWT decodedJWT = jwtVerifier.verify(token);
        return decodedJWT.getClaims();
    }

}
