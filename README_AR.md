# ANAS PORTS PRO v1.1.0
**المطوّر:** Anas Khshan | **الرخصة:** MIT

أداة خفيفة لفحص منافذ TCP على الأنظمة المصرح بفحصها.

## جديد الإصدار 1.1
- قياس زمن استجابة المنافذ.
- تصنيف تقديري إلى مفتوح/مغلق/مفلتر/غير معروف.
- خيار `--show-closed` لعرض الحالات غير المفتوحة.
- تصدير تقارير JSON وHTML.
- تحسين التحقق من أرقام المنافذ وخيارات الأداء.

## التثبيت على Kali Linux
```bash
sudo apt update
sudo apt install -y git python3 python3-venv pipx
git clone https://github.com/YOUR-USERNAME/anas-ports-pro.git
cd anas-ports-pro
pipx install .
```
لتحديث نسخة مثبّتة من مجلد المشروع: `pipx install --force .`

## أمثلة
```bash
anas-ports --help
anas-ports 127.0.0.1 -p 22,80,443
anas-ports 127.0.0.1 -p 1-1024 -o report.json --html report.html
anas-ports 127.0.0.1 -p 1-100 --show-closed
```
استخدم الأداة فقط على الأجهزة والشبكات التي تملكها أو لديك إذن صريح بفحصها. هذه ليست بديلًا كاملًا لـ Nmap؛ لا تدعم UDP أو تحديد نظام التشغيل أو استغلال الثغرات أو كشف إصدارات الخدمات بدقة. فتح المنفذ لا يثبت وجود ثغرة.
