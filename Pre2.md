# What is Drupal

![image](https://user-images.githubusercontent.com/39521088/160287516-e51f072e-a02e-4ff6-81d4-0dad419e24f6.png)

Drupal is a free and open-source web content management system (CMS) written in PHP and distributed under the GNU General Public License. Drupal provides an open-source back-end framework for at least 14% of the top 10,000 websites worldwide – ranging from personal blogs to corporate, political, and government sites. Systems also use Drupal for knowledge management and for business collaboration. As of March 2022, the Drupal community comprised more than 1.39 million members, including 124,000 users actively contributing, resulting in more than 48,300 free modules that extend and customize Drupal functionality, over 3,000 free themes that change the look and feel of Drupal, and at least 1,400 free distributions that allow users to quickly and easily set up a complex, use-specific Drupal in fewer steps. 

The standard release of Drupal, known as Drupal core, contains basic features common to content-management systems. These include user account registration and maintenance, menu management, RSS feeds, taxonomy, page layout customization, and system administration. The Drupal core installation can serve as a simple website, a single- or multi-user blog, an Internet forum, or a community website providing for user-generated content. Drupal also describes itself as a Web application framework. When compared with notable frameworks, Drupal meets most of the generally accepted feature requirements for such web frameworks. Although Drupal offers a sophisticated API for developers, basic Web-site installation and administration of the framework require no programming skills. Drupal runs on any computing platform that supports both a web server capable of running PHP and a database to store content and configuration.

# What is Drupalgeddon2

![image](https://user-images.githubusercontent.com/39521088/160287523-14ca439e-9b59-43c5-a4d4-0db1a955fe1c.png)

On 28 March, the Drupal Security Team announced they identified and patched a critical Remote Code Execution vulnerability (CVE-2018-7600) affecting all Drupal releases to date. As a matter of urgency, they recommended clients update their Drupal websites to the latest version immediately.
At the moment, Drupalgeddon2 exists in all versions prior to 7.58 and 8.5.1. The Drupal Security Team stated that the risk of CVE-2018-7600 is scored 24/25 based on the NIST Common Misuse Scoring System, and it is considered highly critical for the following reasons:

1. The vulnerability can be triggered by simply sending a POST request, therefore it is straightforward to detect and exploit
2. The attack can be leveraged by an unauthenticated user and it does not require any level of privilege
3. There is a high likelihood of attack since this vulnerability exists in default and common module configurations and it is easy to automate
4. The impact is critical.

# What is the impact?

According to the Drupal project usage information this represents over one million sites or about 9% of sites that are running a known CMS according to Builtwith. Soon after the announcement of the vulnerability, proof of concept code (POC) was made publicly available on Github by a Russian security researcher. Quickly after that, threat intelligence services started to notice exploitation attempts in the wild. Hackers used this vulnerability mainly to mine cryptocurrencies on visitor's computers, install ransomware, and steal private data such as PII or credentials of the users from affected servers.


# Vulnerability Background:
The root cause of this vulnerability is related to the Drupal theme rendering system. To create all of its UI elements, Drupal uses Form API, a powerful tool allowing developers to create forms and handle form submissions quickly and easily. To achieve this, the API uses a hierarchical associative array (Render Array) containing the data that will be rendered, as well as some properties which establish how the data should be rendered.
Let's look at an example. Below is a Render Array:

<image width=500 src="https://user-images.githubusercontent.com/39521088/160287534-10ec1755-7563-46dc-b886-eb07bc4e029f.png" />

You can see the associative array. It contains two elements (firstpara and secondpara), both have several parameters. A parameter key can be identified as it always starts with the hashtag # symbol. The #type parameter specifies the type of the HTML element (checkbox, textarea, etc.) and the #markup parameter is used to set HTML that will be output on the form.
The array in the example above is recursively parsed afterward by the Render API and converted into HTML, as shown below.
<image width=500 src="https://user-images.githubusercontent.com/39521088/160287545-6e4cc20b-2f4e-43be-b919-df5756a13aa8.png" />

There are many other parameters that can be used with forms. Some of them provide a way to post-process the rendered output by re-parsing it through a user-supplied function. According to Drupal API documentation, this can be used to cache a view and still have some level of dynamic output.
In an ideal world, the actual output will include HTML comment based tokens, and then the post process can replace those tokens. However, if the user-supplied callback function is not properly validated, a potential attacker might be able to insert malicious functions such as exec, system, eval, etc. to execute system commands, and take over the server. The following four Form API parameters support callback functions and can be leveraged to exploit the CVE-2018–7600 vulnerability:
* #post_render
* #pre_render
* #access_callback
* #lazy_builder


# Vulnerability Discovery:

## 1. Identify the version
First, find out what version of Drupal is used by your target. This will help understand whether the target is vulnerable or not and what exploit you should use. The exploit methods differ between Drupal 7 and Drupal 8 as they are using different APIs.

Below are a few methods to identify the version:
* Check the HTML HEAD tag

  Click the View Source button to analyze the HTML source code of the Target Application. In some cases you will find the version in a meta tag. Do you see the version in this application? It will look like:

  <image width=500 src="https://user-images.githubusercontent.com/39521088/160287565-b8cddc0f-cf9e-4185-a7ec-cdb5b396b2dc.png" />

* Check HTTP headers

  Use the Proxy to intercept any request to the Target Application and analyze the HTTP response. See if you see the X-Generator header:

  <image width=500 src="https://user-images.githubusercontent.com/39521088/160287572-3f5b7b9c-7ba3-44d7-b7d4-0de76e264dea.png" />

* Check if your target has CHANGELOG.txt file

  If the developer did not delete CHANGELOG.txt file you should be able to view it by sending a simple get request.
  Try going to http://drupal.com/CHANGELOG.txt to see if it exists and what version it is running.

* Other files may disclose the version:

  core/CHANGELOG.txt

  includes/bootstrap.inc

  core/includes/bootstrap.inc

## 2. Identify Unauthenticated Forms
The next step is to identify unauthenticated forms (e.g. login/register form, password reset form) since those paths can be used to exploit the vulnerability. To demonstrate the vulnerability, you can use /?q=user/password path which corresponds to the password reset form.
Triggering the vulnerability requires two steps:

(1) Injecting the malicious data through a POST request.

(2) Use the built-in caching mechanism of Drupal to retrieve the output.

First, the API checks if the form exists in the cache and if it has a unique id it exists and it is unnecessary to prepare the form. Next it goes to the build phase and at this point, the form structured array is complete. If there are no errors on the validation phase it will redirect the user to a page and display a success message. Otherwise, it will redirect the user back to the form and remove only failed items.

For example, let's suppose you are trying to register, you fill in all of the form inputs (username, first name, last name, email, phone, etc.), and you hit Submit. You then get an error message saying that the username is already taken. At this point all valid inputs are accepted and completed so you only have to submit the username again.

This happens because Drupal is using a cache mechanism to temporary save the forms into a database. During the next step of the form submission those cached values are retrieved and processed. As mentioned above, we will take advantage of this mechanism to leverage the exploit.
The initial POST request generates an error and the form containing the malicious code is saved to the database. We then retrieve the output through another POST request.


# Exploit Method Analysis
<image width=500 src="https://user-images.githubusercontent.com/39521088/160287591-701f9da8-362c-41d2-b4f5-c90559024bac.png" />

The Drupalgeddon2 vulnerability allows an attacker to remotely execute commands on the targeted system. In practice, any shell command could be executed with the same privileges as the running web server. This is highly critical, as it does not require any form of authentication.

<image width=500 src="https://user-images.githubusercontent.com/39521088/160287611-0b2a40e1-a329-44d9-8d2c-60dff60512d5.png" />

The payload above can be sent to the webserver as a POST request, which allows any remote attacker to execute system commands.

<image width=500 src="https://user-images.githubusercontent.com/39521088/160287622-e75bdcd1-96ae-44e3-a0b3-8a7e6ecf61db.png" />

A specially crafted POST request is required to execute commands on the targeted system, as shown in the image above. The command will echo some text into test.txt, as a proof of concept.

<image width=500 src="https://user-images.githubusercontent.com/39521088/160287642-3664da4a-3017-4853-87c4-b305804cf9cf.png" />


Furthermore, the file text.txt is located on the web server. This confirms that the server is successfully executing the parsed commands from Burp Suite.

<image width=500 src="https://user-images.githubusercontent.com/39521088/160287648-94188560-5b03-47d3-bc81-b4db71b4c557.png" />

Reading internal system files, such as /etc/passwd can also be conducted by exploiting the same vulnerability. This could also allow an attacker to read the settings.php configuration file or other sensitive content located on the system.

<image width=500 src="https://user-images.githubusercontent.com/39521088/160287656-73e855cf-665a-40cb-976d-a895f5a499e9.png" />

If traditional tools (such as wget) are installed on the system, they can be used to download a reverse shell, as shown in the image above. The attacker can, for example, host the payload on a web server. This would allow an attacker to achieve a meterpreter shell on the targeted system.

<image width=500 src="https://user-images.githubusercontent.com/39521088/160287665-7d3be394-c16e-4961-a786-141acae4f9e7.png" />

If wget is not installed, another method is to use create a netcat listener on the targeted system. The attacker can then transfer the payload using netcat as well.

<image width=500 src="https://user-images.githubusercontent.com/39521088/160287672-bc9bf629-a236-4721-a06e-ef0a7e0813da.png" />

Start Metasploit’s multi/handler, set the appropriate values, and visit http://192.168.0.49/meterpreter.php to trigger the payload.

<image width=500 src="https://user-images.githubusercontent.com/39521088/160287679-93668112-b25a-46fa-b38c-c55ab7e81510.png" />

However, what if there are no appropriate system tools available on the targeted system? The payload can then be encoded with base64. The image above shows how the payload is decoded before being assigned as shell.php.

<image width=500 src="https://user-images.githubusercontent.com/39521088/160287689-6166a8bf-5c33-4c85-aad5-51d65ebfe779.png" />

Moreover, the base64 payload was successfully decoded and stored by the targeted system. Visting http://192.168.0.49/shell.php triggered the payload and connected to the netcat listener on port 1234.

# Public Exploits

Reports from Drupal experts in coordination with security researchers indicated that the default configuration, including a majority of fully developed configurations, has fields in the new user registration page that were not correctly sanitized prior to the Drupal patch. The default page at /user/register can be forced to send a specifically crafted AJAX request that can target a variety of form fields, including ones affected by the vulnerability and thus execute the attacker’s code. Proof-of-concept (POC) code was released into the wild confirming these findings on April 12, 2018. Initial POC targeted the mail[] array utilizing the #post_render function to execute the PHP function exec, which executes underlying operating system functions in the context of the web server user. Below is traffic captured to a vulnerable Drupal instance at local address 10.3.228.197. The PHP command it used is exec, and the payload is a simple wget command to an outside IP address 172.217.6.36.

![image](https://user-images.githubusercontent.com/39521088/160296671-747ba7c8-8743-4573-8e2c-3d4bcb89a95d.png)

Exploitation for known POCs is possible when passed by both POST content types: application/x-www-form-urlencoded and multipart/form-data.

<image width=500 src="https://user-images.githubusercontent.com/39521088/160287709-8437d09a-a311-4850-9198-ad7e95cee030.png" />

A second POC found in the wild targets the timezone form field. The server responds with a HTTP 500 Service unavailable response, although the exploitation is successful.

![image](https://user-images.githubusercontent.com/39521088/160296698-9042c730-1fb3-4ed8-8f85-5fe8b72f2e6e.png)

<image width=500 src="https://user-images.githubusercontent.com/39521088/160296741-a1412892-eb53-4f75-8119-df13520e3954.png" />

The first publicly available POCs to appear have only been effective on vulnerable Drupal 8.x instances due to the default configuration of the /user/register page on 8.x versus 7.x. Other default configuration URIs include the /user/password page, which can exploit 7.x versions successfully. This particular exploit targets the _triggering_element_name form and requires two requests to be sent.

![image](https://user-images.githubusercontent.com/39521088/160296791-dfe2ccf8-c826-449b-8470-4ad7bf3e11eb.png)

At the time of this analysis, exploits in the wild are attempting to call wget, curl, and other second-stage mechanisms on malicious payloads in order to initiate a takeover of Drupal sites. As with any remote code execution vulnerability, weaponized payloads containing reverse shells, backdoors, botnets, and even crypto-miners have been detected in the wild.

Palo Alto Networks Next Generation Firewall signatures prevent these POC in-the-wild exploits, as well as the potential exploits described below.

Potential Exploits:
Nearly all publicly available POC samples exploited vulnerable instances of Drupal by passing a render array key of `[#post_render][]` with a value of the PHP function exec, followed by a second key-value pair `[#markup]` with a value of an operating system function to be called by exec.
However, other successful exploits can and do take advantage of the four Form API functions listed above (`[#post_render], [#pre_render], [#access_callback], and [#lazy_builder]`).

In the interest of signature development, we at Palo Alto Networks cover traffic exploiting these API functions, as well as other ‘dangerous’ PHP functions that may be exploited. PHP functions that should be screened include:
`Exec\system\popen\pcntl_exec\eval\preg_replace\create_function\include\require\passthru\shell_exec\proc_open\assert\include_once\require_once\$_GET\$_POST\$_SERVER\$_FILES\$_REQUEST\$_SESSION\$_ENV\$_COOKIE`

Aside from exec, malware samples in the wild include system, passthru, and eval. It is certainly possible that more elaborate attackers will be able to craft requests to take advantage of these functions.

Exploit Samples in the Wild:

<image width=500 src="https://user-images.githubusercontent.com/39521088/160287736-ebc43016-7812-4d33-ae9b-741c007c40e3.png" />

Reference:
1. https://www.cvedetails.com/cve-details.php?t=1&cve_id=CVE-2018-7600
2. https://en.wikipedia.org/wiki/Drupal
3. https://www.hackedu.com/blog/drupalgeddon2-cve-2018-7600-vulnerability
4. https://groups.drupal.org/security/faq-2018-002
5. https://www.toxicsolutions.net/2020/07/exploiting-drupalgeddon2-cve-2018-7600/
6. https://unit42.paloaltonetworks.com/unit42-exploit-wild-drupalgeddon2-analysis-cve-2018-7600/
