Adding a model
==============

To add a new model we need to get some information to do the following things:
1. Auto-detect the model
2. Log in
3. Log out
4. Check if we are logged in
5. Get the connected devices via LAN
6. Get the connected devices via WiFi

To get this information you should use your own browser and report the requested information. Hopefully this is enough to add support for your model, but chances are this is not enough.

Before beginning, the first thing you should know is IP your router has. You can enter this IP-address in your browser and a web-interface/page should pop up. Usually this is something like:
- 192.168.1.1
- 192.168.178.1

The rest of this guide will use 192.168.178.1 as an example, but you should replace it with your own address.

Most steps will ask you to view the page source of a webpage and save this information. In Chrome and Firefox you can do this by right clicking in the page and choose Inspect (Chrome) or Inspect Element (Firefox.) It usually helps if you give more information than just the element-source. Feel free to save the whole page and attach the file to the issue.

Auto-detect the model
---------------------

Go to this address in your browser: http://192.168.178.1/RootDevice.xml (Change the IP in the URL with the IP of your router.) If you get a 404 (Page not found) or an error, skip the rest of this step.

Save the file and add it to the issue.

Logging in
----------

Go to the this address in your browser: http://192.168.178.1/ (Change the IP in the URL with the IP of your router.) You should see a login page from your router. Please view the source of the login form (e.g., right click on the username-field and slect Inspect/Inspect Element) and save the information. For my model this looks something like:
```
<form action="/goform/loginMR3" method="POST" name="loginMR3">
                <fieldset>
                    <div class="form-field">
                        <label><strong>Gebruikersnaam</strong></label>
                        <div class="field">
                            <input type="text" name="loginUsername" value="" class="invoer">
                        </div>
                    </div>
                    <div class="form-field">
                        <label><b>Wachtwoord</b></label>
                        <div class="field">
                            <input type="password" name="loginPassword" value="" class="invoer">
                        </div>
                    </div>
                    <div class="form-field">
                        <div class="field">
                            <input type="submit" value="inloggen &nbsp;&nbsp;&nbsp; ›" class="button orange large right">
                        </div>
                    </div>
                </fieldset>
            </form>
```

Do note that the text in this form is Dutch. My router is a Ziggo/UPC re-branded Ubee model. Your model might be brand- and/or language-specific as well.

Logging out
-----------

Log in into the webinterface of your router and find the log out link. Right click on the logout link and save the URL. For my model it is: http://192.168.178.1/logout.asp

Check if we are logged in
-------------------------

To ensure we can get the right information (connected devices via LAN/WAN), we need to know that we are logged in correctly. Usually, if you go to the URL for step 6 (connected devices via WiFi), and you're not logged in, you're redirected to the login page. Find a text specific for this login page, view the source of the text and save the information.

For my model this is part of the login form:
```
  <input type="text" name="loginUsername" value="" class="invoer">
```

Get the connected devices via LAN
---------------------------------

Find the page which shows the connected devices via LAN. On some models, this is the same page as the devices connected via WiFi. Find the table which shows the list of connected devices. For my model this page is called DHCP, the URL is http://192.168.178.1/RgDhcp.asp. Find the table which shows the list of devices, view the source of this element and attach it to the issue. Feel free to change any information you feel is sensitive. But please do keep the format in tact. In my case the source of the table looks like this (partial):
```
<table style="font-family: Helvetica;font-size:14">
  <tbody>
    <tr bgcolor="#0088ce"><td>MAC Address</td><td>IP Address</td><td>Subnet Mask</td><td>Duration</td><td>Expires</td><td>Select</td></tr>
    <tr bgcolor="#99CCFF"><td>ffeeddccbbaa</td><td>192.168.178.010</td><td>255.255.255.000</td><td>D:01 H:00 M:00 S:00</td><td>Tue May 21 14:25:44 2019</td><td align="center"><input type="radio" name="lease" onclick="selectedLease(1);"></td></tr>
    <tr bgcolor="#9999CC"><td>001122334466</td><td>192.168.178.011</td><td>255.255.255.000</td><td>D:01 H:00 M:00 S:00</td><td>Mon May 20 19:19:59 2019</td><td align="center"><input type="radio" name="lease" onclick="selectedLease(2);"></td></tr>
  </tbody>
</table>
```

Get the connected devices via WiFi
----------------------------------

Find the page which shows the connected devices via WiFi. On some models, this is the same page as the devices connected via LAN. Find the table which shows the list of connected devices. For my model this page is called Wireless - Access Control, the URL is http://192.168.178.1/wlanAccess.asp. Find the table which shows the list of devices, view the source of this element and attach it to the issue. Feel free to change any information you feel is sensitive. But please do keep the format in tact. In my case the source of the table looks like this (partial):
```
<table>
  <tbody>
    <tr bgcolor="#0088ce"><td>&nbsp;MAC Address&nbsp;</td><td>&nbsp;Age(s)&nbsp;</td><td>&nbsp;RSSI(dBm)&nbsp;</td><td>&nbsp;IP Addr&nbsp;</td><td>&nbsp;Host Name&nbsp;</td><td>Mode</td><td>Speed (kbps)</td></tr><tr bgcolor="#99CCFF"><td>18:F0:E4:25:81:AC</td><td>12069</td><td>-63</td><td></td><td></td><td>n</td><td>6000</td></tr>
    <tr bgcolor="#9999CC"><td>FF:EE:DD:CC:BB:AA</td><td>12236</td><td>-56</td><td>192.168.178.10</td><td></td><td>n</td><td>6000</td></tr>
    <tr bgcolor="#99CCFF"><td>00:11:22:33:44:55</td><td>110732</td><td>-84</td><td></td><td></td><td>n</td><td>6500</td></tr>
  </tbody>
</table>
```

Finalizing
----------

Hopefully this small guide shows how to get the information needed to support your model. Save the information in the issue. Feel free to save the whole page for each item, instead of just adding snippets. If you feel that the information is sensitive and don't want to add it to a public page, feel free to send it to the owner(s) of this repository.
