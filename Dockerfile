FROM devopsfaith/krakend:2.9.3

COPY krakend.tmpl .
COPY krakend-cognito-jwt/krakend-cognito-jwt.so /usr/local/krakend/plugins/
CMD ["run", "-c", "krakend.tmpl"]