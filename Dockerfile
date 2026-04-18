# ⚠️  INSECURE DOCKERFILE — FOR TRAINING PURPOSES ONLY (Lab 3)
# Used to demonstrate container security anti-patterns.
# DO NOT use in any real environment.
#
# Security problems to find in Lab 3 (hint: there are 5):
# 1. _________________________________________________
# 2. _________________________________________________
# 3. _________________________________________________
# 4. _________________________________________________
# 5. _________________________________________________

FROM openjdk:17-jdk
WORKDIR /app
COPY target/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
