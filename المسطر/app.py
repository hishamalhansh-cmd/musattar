from flask import Flask, render_template_string, request

app = Flask(__name__)

workers = [
{
"name":"حسن النجار",
"city":"بغداد",
"exp":"10 سنوات",
"phone":"+964784145165",
"rating":"4.3",
"images":[
"https://picsum.photos/400/300",
"https://picsum.photos/401/300",
"https://picsum.photos/402/300"
]
}
]

html = """

<!DOCTYPE html>
<html lang="ar">
<head>
<meta charset="UTF-8">
<title>المسطر</title>

<style>

body{
font-family:Arial;
background:#0f172a;
color:white;
margin:0;
}

.header{
background:#020617;
padding:15px;
display:flex;
justify-content:space-between;
}

.logo{
font-size:22px;
font-weight:bold;
}

.search{
text-align:center;
margin:30px;
}

.search input{
padding:10px;
width:250px;
border-radius:8px;
border:none;
}

.cards{
display:grid;
grid-template-columns:repeat(auto-fit,minmax(280px,1fr));
gap:20px;
padding:20px;
}

.card{
background:#1e293b;
padding:20px;
border-radius:15px;
}

.gallery{
display:grid;
grid-template-columns:1fr 1fr;
gap:5px;
}

.gallery img{
width:100%;
border-radius:10px;
}

.rating{
color:#fbbf24;
margin:10px 0;
}

.btns a{
padding:10px 15px;
border-radius:10px;
text-decoration:none;
color:white;
margin:5px;
display:inline-block;
}

.call{
background:#22c55e;
}

.whatsapp{
background:#25D366;
}

</style>

</head>

<body>

<div class="header">
<div class="logo">المسطر</div>
</div>

<div class="search">
<input placeholder="ابحث عن عامل...">
</div>

<div class="cards">

{% for w in workers %}

<div class="card">

<h2>{{w.name}}</h2>

<div class="rating">
⭐⭐⭐⭐☆ {{w.rating}} / 5
</div>

<div class="gallery">
{% for img in w.images %}
<img src="{{img}}">
{% endfor %}
</div>

<p>📍 {{w.city}}</p>
<p>💼 الخبرة: {{w.exp}}</p>

<div class="btns">

<a class="call" href="tel:{{w.phone}}">
📞 اتصال
</a>

<a class="whatsapp"
href="https://wa.me/{{w.phone.replace('+','')}}">
💬 واتساب
</a>

</div>

</div>

{% endfor %}

</div>

</body>
</html>

"""

@app.route("/")
def home():
return render_template_string(html,workers=workers)

if __name__=="__main__":
import os
port=int(os.environ.get("PORT",10000))
app.run(host="0.0.0.0",port=port)
