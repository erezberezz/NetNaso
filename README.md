# NetNaso
A newtork analysis tool able to capture and analyze packets, visualize traceroute and make GeoIP look ups.
I was inspired to make this tool following a course I did of Computer Networks during my exchange semester in Polito.

The tool is built of diffrenet tabs
![image](https://github.com/user-attachments/assets/a5257d92-a495-49b9-b914-70810a0bd992)


A traceroute tab which includes visualization on the world map, and the ability to set a max hop amount
as an example, here are the results when ran with google's DNS server 8.8.8.8
![image](https://github.com/user-attachments/assets/5576c250-adb1-4dbc-aca1-797ed6e4c34e)
and we get the following fully interactive traceroute map
![image](https://github.com/user-attachments/assets/f3df9065-a6e9-4234-8e5f-5d43d6671382)
The traceroute also supports domain names and IPv6 addresses.

On the GeoIP tab we have the option to look up the location of any ip address we desire
![image](https://github.com/user-attachments/assets/14ba2f1d-58d3-45b2-a71c-c4c1a4d32608)

And last but not least, I have also implemented a network speed trends graph that periodcally checks and plots download/upload speed
![image](https://github.com/user-attachments/assets/aecbdfc8-9ec6-4410-ae4d-2f6096d16e8a)

