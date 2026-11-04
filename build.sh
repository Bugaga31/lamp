#!/usr/bin/env bash
# bash | build.sh | собирает APK без Gradle: javac -> d8 -> aapt2 -> zipalign -> apksigner
set -euo pipefail
: "${ANDROID_HOME:?нужен ANDROID_HOME с platforms/android-34 и build-tools/34.0.0}"
: "${JAVA_HOME:?нужен JDK 17}"
export PATH="$JAVA_HOME/bin:$PATH"

AJ="$ANDROID_HOME/platforms/android-34/android.jar"
BT="$ANDROID_HOME/build-tools/34.0.0"
BC="${BC_JAR:-bcprov-jdk18on-1.78.1.jar}"

rm -rf obj dex out && mkdir -p obj dex out
javac -encoding UTF-8 -source 8 -target 8 -nowarn -classpath "$AJ:$BC" -d obj $(find app/src -name '*.java')
"$BT/d8" --lib "$AJ" --min-api 24 --output dex $(find obj -name '*.class') "$BC"
"$BT/aapt2" compile --dir app/res -o out/res.zip
"$BT/aapt2" link -o out/base.apk -I "$AJ" --manifest app/AndroidManifest.xml \
  -R out/res.zip --auto-add-overlay --min-sdk-version 24 --target-sdk-version 34 \
  --version-code 1 --version-name 1.0
cp out/base.apk out/app.apk
(cd dex && zip -q ../out/app.apk classes.dex)
"$BT/zipalign" -f 4 out/app.apk out/app-aligned.apk
[ -f out/debug.keystore ] || keytool -genkeypair -keystore out/debug.keystore -alias k \
  -storepass android -keypass android -dname "CN=LAMPA Pull" -keyalg RSA -keysize 2048 -validity 10000
"$BT/apksigner" sign --ks out/debug.keystore --ks-pass pass:android --key-pass pass:android \
  --out release/LAMPA-Pull.apk out/app-aligned.apk
echo "ok: release/LAMPA-Pull.apk"
