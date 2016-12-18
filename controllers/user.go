package controllers

import (
	"acme/models"
	pk "acme/utilities/pbkdf2"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/alexcesaro/mail/gomail"
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/orm"
	"github.com/astaxie/beego/validation"
	"github.com/twinj/uuid"
)

func (this *MainController) Login() {
	this.activeContent("user/login")

	back := strings.Replace(this.Ctx.Input.Param(":back"), ">", "/", -1) // allow for deeper URL such as l1/l2/l3 represented by l1>l2>l3
	fmt.Println("back is", back)
	if this.Ctx.Input.Method() == "POST" {
		flash := beego.NewFlash()
		email := this.GetString("email")
		password := this.GetString("password")
		valid := validation.Validation{}
		valid.Email(email, "email")
		valid.Required(password, "password")
		if valid.HasErrors() {
			errormap := []string{}
			for _, err := range valid.Errors {
				errormap = append(errormap, "Validation failed on "+err.Key+": "+err.Message+"\n")
			}
			this.Data["Errors"] = errormap
			return
		}
		fmt.Println("Authorization is", email, ":", password)

		//******** Read password hash from database
		var x pk.PasswordHash

		x.Hash = make([]byte, 32)
		x.Salt = make([]byte, 16)

		o := orm.NewOrm()
		o.Using("default")
		user := models.AuthUser{Email: email}
		err := o.Read(&user, "Email")
		if err == nil {
			if user.Reg_key != "" {
				flash.Error("Account not verified")
				flash.Store(&this.Controller)
				return
			}

			// scan in the password hash/salt
			fmt.Println("Password to scan:", user.Password)
			if x.Hash, err = hex.DecodeString(user.Password[:64]); err != nil {
				fmt.Println("ERROR:", err)
			}
			if x.Salt, err = hex.DecodeString(user.Password[64:]); err != nil {
				fmt.Println("ERROR:", err)
			}
			fmt.Println("decoded password is", x)
		} else {
			flash.Error("No such user/email")
			flash.Store(&this.Controller)
			return
		}

		//******** Compare submitted password with database
		if !pk.MatchPassword(password, &x) {
			flash.Error("Bad password")
			flash.Store(&this.Controller)
			return
		}

		//******** Create session and go back to previous page
		m := make(map[string]interface{})
		m["first"] = user.First
		m["username"] = email
		m["timestamp"] = time.Now()
		this.SetSession("acme", m)
		this.Redirect("/"+back, 302)
	}
}

func (this *MainController) Logout() {
	this.activeContent("logout")
	this.DelSession("acme")
	this.Redirect("/home", 302)
}

func (this *MainController) Register() {
	this.activeContent("user/register")

	if this.Ctx.Input.Method() == "POST" {
		flash := beego.NewFlash()
		first := this.GetString("first")
		last := this.GetString("last")
		email := this.GetString("email")
		password := this.GetString("password")
		password2 := this.GetString("password2")

		valid := validation.Validation{}
		valid.Required(first, "first")
		valid.Email(email, "email")
		valid.MinSize(password, 6, "password")
		valid.Required(password2, "password2")

		if valid.HasErrors() {
			errormap := []string{}
			for _, err := range valid.Errors {
				errormap = append(errormap, "Validation failed on "+err.Key+": "+err.Message+"\n")
			}

			this.Data["Errors"] = errormap
			return
		}

		if password != password2 {
			flash.Error("Passwords don't match")
			flash.Store(&this.Controller)
			return
		}

		h := pk.HashPassword(password)

		o := orm.NewOrm()
		o.Using("Default")

		user := models.AuthUser{First: first, Last: last, Email: email}

		user.Password = hex.EncodeToString(h.Hash) + hex.EncodeToString(h.Salt)

		u := uuid.NewV4()
		user.Reg_key = u.String()
		_, err := o.Insert(&user)
		if err != nil {
			flash.Error(email + " already registered")
			flash.Store(&this.Controller)
			return
		}

		if !sendVerification(email, u.String()) {
			flash.Error("Unable to send verification email")
			flash.Store(&this.Controller)
			return
		}

		flash.Notice("Your account has been created. You must verify the account in your email.")
		flash.Store(&this.Controller)
		this.Redirect("/notice", 302)

	}
}

func sendVerification(email, u string) bool {
	link := "http://localhost:8080/user/verify/" + u
	host := "smtp.gmail.com"
	port := 587
	msg := gomail.NewMessage()
	msg.SetAddressHeader("From", "jibran.kalia@gmail.com", "Kalia Corporation")
	msg.SetHeader("To", email)
	msg.SetHeader("Subject", "Account Verification for Kalia Corporation")
	msg.SetBody("text/html", "To verify your account, please click on the link: <a href=\""+link+
		"\">"+link+"</a><br><br>Best Regards,<br>Kalia Corporation")
	m := gomail.NewMailer(host, "jibran.kalia@gmail.com", "1Jib2gm3", port)
	if err := m.Send(msg); err != nil {
		return false
	}
	return true
}

func (this *MainController) Verify() {
	this.activeContent("user/verify")

	u := this.Ctx.Input.Param(":uuid")
	o := orm.NewOrm()
	o.Using("default")
	user := models.AuthUser{Reg_key: u}
	err := o.Read(&user, "Reg_key")
	if err == nil {
		this.Data["Verified"] = 1
		user.Reg_key = ""
		if _, err := o.Update(&user); err != nil {
			delete(this.Data, "Verified")
		}
	}
}
