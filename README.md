# NessusPrivCheck
Automate privilege checking

docker build -t php-audit-app .
docker run -d -p 8181:80 --name audit-app php-audit-app
