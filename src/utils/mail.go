package utils

import (
	"fmt"
	"os"
	"strconv"

	"gopkg.in/gomail.v2"
)

func getSignupTemplate(otp uint, link string) string {
	template := fmt.Sprintf(`<div style="font-family: Helvetica,Arial,sans-serif;min-width:1000px;overflow:auto;line-height:2">
                <div style="margin:20px auto;width:1000px;padding:20px 0">
                    <div style="border-bottom:1px solid #eee">
                    <a href="" style="font-size:1.5rem;color: #00466A;text-decoration:none;font-weight:600">FastAPI</a>
                    </div>
                    <p style="font-size:1.1em">Hi there,</p>
                    <p>Thank you for choosing FastAPI. Use the following OTP to complete your email verification process. OTP is valid for 10 minutes</p>
                    <h2 style="background: #00466A;margin: 0 auto;width: max-content;padding: 0 10px;color: #fff;border-radius: 4px;">%d</h2>
                    %s
                    <p style="font-size:0.9em;">Regards,<br />FastAPI</p>
                    <hr style="border:none;border-top:1px solid #eee" />
                    <div style="float:right;padding:8px 0;color:#aaa;font-size:0.8em;line-height:1;font-weight:300">
                    <p>FastAPI. Inc</p>
                    <p>1600 Amphitheatre Parkway</p>
                    <p>California</p>
                    </div>
                </div>
                </di>`, otp, link)
	return template
}

func SendOTP(email string, otp uint, link string) error {
	MAIL_SERVER := os.Getenv("MAIL_SERVER")
	MAIL_PORT := os.Getenv("MAIL_PORT")
	MAIL_FROM := os.Getenv("MAIL_FROM")
	MAIL_PASSWORD := os.Getenv("MAIL_PASSWORD")
	message := gomail.NewMessage()
	message.SetHeader("From", MAIL_FROM)
	message.SetHeader("To", email)
	message.SetHeader("Subject", "OTP for email verification")
	message.SetBody("text/html", getSignupTemplate(otp, link))
	fmt.Println(MAIL_SERVER)
	port, err := strconv.Atoi(MAIL_PORT)
	if err != nil {
		fmt.Println("Error converting MAIL_PORT to int:", err)
		return err
	}

	dialer := gomail.NewDialer(MAIL_SERVER, port, MAIL_FROM, MAIL_PASSWORD)

	if err := dialer.DialAndSend(message); err != nil {
		fmt.Println("Error sending email:", err)
		return err
	}
	return nil
}
