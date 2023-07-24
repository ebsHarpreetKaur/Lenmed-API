from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
import smtplib
# from os.path import dirname as os_dirname, abspath as os_abspath
import os
from Hospital_Management import settings
from email import encoders
from email.header import Header
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr
from sys import exc_info


# def send_html_email(receiver_emial, reciver_name, otp):
#     subject = 'Password Reset'
#     from_email = 'gcrew.joban@gmail.cpm'
#     recipient_list = [receiver_emial]

#     root_path = os_dirname(os_dirname(os_abspath(__file__)))
#     root_path = str(root_path) + '/accounts/templates/passwordRecovery.html'

#     # Load the HTML template
#     html_message = render_to_string(root_path, {
#         'name': reciver_name,
#         'email': receiver_emial,
#         'otp': otp
#     })

#     # Create the plain text version of the message
#     text_message = strip_tags(html_message)

#     # Send the email
#     email = EmailMultiAlternatives(subject, text_message, from_email, recipient_list)
#     email.attach_alternative(html_message, "text/html")
#     email.send()


def SendEmail(to_email, message, subject, attach=None, CC=None):
    try:
        """method to send email"""
        mailer_name = settings.SMTP_MAILER_NAME
        me = formataddr((str(Header(mailer_name, 'utf-8')), settings.SMTP_FROM_EMAIL))

        # Create message container - the correct MIME type is multipart/alternative.
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = me

        if CC is not None:
            msg['CC'] = CC

        html = message

        msg['To'] = to_email
        part2 = MIMEText(html, 'html')

        msg.attach(part2)

        if attach is not None:
            for f in attach:
                part = MIMEBase('application', "octet-stream")
                part.set_payload(open(f, "rb").read())
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', 'attachment; filename="{0}"'
                                .format(os.path.basename(f)))
                msg.attach(part)

        mail = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT)

        mail.ehlo()

        mail.starttls()
        mail.login(settings.SMTP_FROM_EMAIL, settings.SMTP_PASSWORD)
        mail.sendmail(me, to_email, msg.as_string())
        print("----mail---sent------")
        mail.quit()

    except:
        print("--error->>>", exc_info())
