<<<<<<< HEAD
# Security Monitoring System | نظام المراقبة الأمنية

## 🔒 Overview | نظرة عامة

This is a comprehensive **Security Monitoring System** consisting of two main components:

هذا المشروع عبارة عن **نظام مراقبة أمنية متكامل** يتكون من مكونين رئيسيين:

### 1. Web Authentication Platform | منصة التحقق من الهوية على الويب
- Secure user registration and login system
- Real-time monitoring of security attacks
- Protection against brute force attacks
- نظام آمن لتسجيل المستخدمين وتسجيل الدخول
- مراقبة الهجمات الأمنية في الوقت الفعلي
- الحماية من هجمات القوة الغاشمة

### 2. Advanced Log Analyzer | محلل السجلات المتقدم
- Professional GUI application for security analysis
- Detection of 25+ types of cyber attacks
- Comprehensive reporting and visualization
- تطبيق واجهة رسومية احترافية لتحليل الأمان
- اكتشاف أكثر من 25 نوع من الهجمات السيبرانية
- تقارير شاملة ومرئيات تفاعلية

## 🚀 Features | المميزات

### Web Application | تطبيق الويب
- ✅ **Secure Authentication** | المصادقة الآمنة
  - User registration with password hashing
  - Secure login system
  - Account management (delete account)

- 🛡️ **Security Monitoring** | المراقبة الأمنية
  - Real-time IP tracking
  - Failed login attempt monitoring
  - Brute force attack detection
  - Automatic suspicious activity logging

- 📊 **Activity Logging** | تسجيل الأنشطة
  - Complete user activity logs
  - Failed attempt tracking
  - Security incident reports

### Log Analyzer | محلل السجلات
- 🎯 **Attack Detection** | اكتشاف الهجمات
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Command Injection
  - Path Traversal
  - Local/Remote File Inclusion (LFI/RFI)
  - Server-Side Template Injection (SSTI)
  - And 20+ more attack types

- 📈 **Advanced Analytics** | التحليلات المتقدمة
  - Real-time dashboard
  - Attack distribution charts
  - Suspicious IP analysis
  - Risk scoring system

- 🎨 **Modern Interface** | الواجهة الحديثة
  - Dark/Light theme support
  - Interactive charts and graphs
  - Professional reporting
  - Export capabilities

## 🛠️ Installation | التثبيت

### Prerequisites | المتطلبات المسبقة
- Python 3.7 or higher
- pip package manager

### Setup Steps | خطوات التثبيت

1. **Clone the repository | استنساخ المستودع**
```bash
git clone <repository-url>
cd DigitalProject
```

2. **Create virtual environment (recommended) | إنشاء بيئة افتراضية (مستحسن)**
```bash
python -m venv venv
# On Windows | على ويندوز:
venv\Scripts\activate
# On Linux/Mac | على لينكس/ماك:
source venv/bin/activate
```

3. **Install dependencies | تثبيت التبعيات**
```bash
pip install -r requirements.txt
```

4. **Create necessary directories | إنشاء المجلدات الضرورية**
```bash
mkdir data
mkdir assets
```

## 🚀 Usage | الاستخدام

### Running the Web Application | تشغيل تطبيق الويب
```bash
python app.py
```
- Open your browser and navigate to `http://localhost:5000`
- افتح المتصفح واذهب إلى `http://localhost:5000`

### Running the Log Analyzer | تشغيل محلل السجلات
```bash
python log_analyzer.py
```

## 📁 Project Structure | هيكل المشروع

```
DigitalProject/
├── app.py                  # Main Flask web application | التطبيق الرئيسي
├── log_analyzer.py         # GUI Log analyzer | محلل السجلات الرسومي
├── requirements.txt        # Python dependencies | التبعيات
├── README.md              # Project documentation | التوثيق
├── data/                  # Log files directory | مجلد ملفات السجلات
│   ├── Weblogs.csv       # Web activity logs | سجلات نشاط الويب
│   └── reports.txt       # Security reports | التقارير الأمنية
├── styles/               # CSS stylesheets | ملفات التنسيق
│   └── style.css
├── templates/            # HTML templates | قوالب HTML
│   ├── base.html        # Base template | القالب الأساسي
│   ├── index.html       # Home page | الصفحة الرئيسية
│   ├── login.html       # Login page | صفحة تسجيل الدخول
│   ├── register.html    # Registration page | صفحة التسجيل
│   └── dashboard.html   # User dashboard | لوحة تحكم المستخدم
├── assets/              # Static assets | الأصول الثابتة
└── instance/            # Database files | ملفات قاعدة البيانات
    └── users.db         # SQLite database | قاعدة بيانات SQLite
```

## 🔍 Security Features | المميزات الأمنية

### Detected Attack Types | أنواع الهجمات المكتشفة
1. **SQL Injection** | حقن SQL
2. **Cross-Site Scripting (XSS)** | البرمجة النصية عبر المواقع
3. **Command Injection** | حقن الأوامر
4. **Path Traversal** | اجتياز المسار
5. **Local/Remote File Inclusion** | تضمين الملفات المحلية/البعيدة
6. **Server-Side Template Injection** | حقن القوالب من جانب الخادم
7. **Cross-Site Request Forgery (CSRF)** | تزوير الطلبات عبر المواقع
8. **XML External Entity (XXE)** | كيان XML خارجي
9. **Brute Force Attacks** | هجمات القوة الغاشمة
10. **Denial of Service (DoS)** | رفض الخدمة
11. **JWT Attacks** | هجمات الرموز المميزة
12. **Business Logic Flaws** | عيوب منطق الأعمال
13. **Privilege Escalation** | تصعيد الامتيازات
14. **File Upload Vulnerabilities** | نقاط ضعف تحميل الملفات
15. **And many more...** | والمزيد...

### Security Monitoring | المراقبة الأمنية
- **Real-time IP tracking** | تتبع IP في الوقت الفعلي
- **Failed attempt analysis** | تحليل المحاولات الفاشلة
- **Risk scoring system** | نظام تسجيل المخاطر
- **Automated reporting** | الإبلاغ التلقائي
- **Attack pattern recognition** | التعرف على أنماط الهجوم

## 📊 Analytics & Reporting | التحليلات والتقارير

### Dashboard Metrics | مقاييس لوحة التحكم
- Total login attempts | إجمالي محاولات تسجيل الدخول
- Failed vs successful logins | تسجيل الدخول الفاشل مقابل الناجح
- Registration attempts | محاولات التسجيل
- Suspicious IP addresses | عناوين IP المشبوهة
- Attack type distribution | توزيع أنواع الهجمات

### Visual Analytics | التحليلات المرئية
- **Pie charts** for attack distribution | الرسوم البيانية الدائرية لتوزيع الهجمات
- **Bar charts** for login/registration trends | الرسوم البيانية الشريطية لاتجاهات تسجيل الدخول/التسجيل
- **Timeline analysis** of security events | تحليل الجدول الزمني للأحداث الأمنية
- **Risk assessment** visualizations | مرئيات تقييم المخاطر

## ⚙️ Configuration | التكوين

### Security Settings | إعدادات الأمان
- Change the `SECRET_KEY` in `app.py` for production
- Configure database settings for production use
- Set up proper logging levels
- غيّر `SECRET_KEY` في `app.py` للإنتاج
- كوّن إعدادات قاعدة البيانات للاستخدام الإنتاجي
- اضبط مستويات التسجيل المناسبة

### Customization | التخصيص
- Modify attack patterns in `log_analyzer.py`
- Adjust security thresholds
- Customize reporting formats
- عدّل أنماط الهجوم في `log_analyzer.py`
- اضبط عتبات الأمان
- خصص تنسيقات التقارير

## 🎯 Use Cases | حالات الاستخدام

- **Small to medium businesses** needing security monitoring
- **Educational institutions** for cybersecurity training
- **Security researchers** for attack pattern analysis
- **Web developers** learning about security best practices
- **الشركات الصغيرة والمتوسطة** التي تحتاج إلى مراقبة أمنية
- **المؤسسات التعليمية** لتدريب الأمن السيبراني
- **باحثو الأمان** لتحليل أنماط الهجوم
- **مطورو الويب** لتعلم أفضل الممارسات الأمنية

## 🔧 Troubleshooting | استكشاف الأخطاء وإصلاحها

### Common Issues | المشاكل الشائعة

1. **Port already in use** | المنفذ قيد الاستخدام بالفعل
   ```bash
   # Change port in app.py
   app.run(port=5001)
   ```

2. **Missing data directory** | مجلد البيانات مفقود
   ```bash
   mkdir data
   ```

3. **Database errors** | أخطاء قاعدة البيانات
   ```bash
   # Reset database
   rm instance/users.db
   python app.py
   ```
هذا المشروع مفتوح المصدر ومتاح تحت ترخيص MIT.

## 🤝 Contributing | المساهمة

Contributions are welcome! Please feel free to submit a Pull Request.

المساهمات مرحب بها! لا تتردد في إرسال طلب سحب.

---

**Built with ❤️ for cybersecurity education and monitoring**

**تم البناء بـ ❤️ لتعليم ومراقبة الأمن السيبراني**
=======
# securewatch-analytic
Python security suite: Flask login firewall, real-time attack logging, and a GUI analyzer that visualizes 25 + threat types.
>>>>>>> 3917fa0603fa6d493417e68c0ef477579a6432b5
