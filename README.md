## syn_flood_demo.py output
```bash
time     phase      SYN/s  SYN-ACK  ratio   H-open  srcs  status
-------- ---------- ------ ------- ------ ------- ----- --------
14:03:34 Baseline        1       0    1.0    100%     1 OK      
14:03:35 Baseline        4       4    1.0      0%     6 OK      
14:03:36 Baseline        5       5    1.0      0%     6 OK      
14:03:37 Baseline        5       5    1.0      0%     6 OK      
14:03:38 Baseline        5       5    1.0      0%     6 OK      
14:03:39 Ramp-up         9       4    2.2     56%    10 OK      
14:03:40 Ramp-up        76      15    5.1     80%    82 ELEV    
14:03:41 Ramp-up        81      14    5.8     83%    82 ELEV    
14:03:42 Ramp-up        77      20    3.9     74%    82 ELEV    
14:03:43 Attack         69       8    8.6     88%    70 ELEV    
--- alert start: syn=408/s ratio=19.4 hopen=95%
14:03:44 Attack        408      21   19.4     95%   409 ALERT   
14:03:45 Attack        406      23   17.7     94%   408 ALERT   
14:03:46 Attack        407      18   22.6     96%   408 ALERT   
14:03:47 Attack        406      25   16.2     94%   410 ALERT   
14:03:48 Attack        407      24   17.0     94%   408 ALERT   
14:03:49 Attack        405      21   19.3     95%   408 ALERT   
14:03:50 Attack        406      21   19.3     95%   410 ALERT   
14:03:51 Peak          324      16   20.2     95%   325 ALERT   
14:03:52 Peak          702      10   70.2     99%   703 ALERT   
14:03:53 Peak          695      18   38.6     97%   696 ALERT   
14:03:54 Peak          695      18   38.6     97%   697 ALERT   
14:03:55 Peak          694      17   40.8     98%   695 ALERT   
14:03:56 Peak          700      12   58.3     98%   701 ALERT   
14:03:57 Recovery      551      10   55.1     98%   553 ALERT   
14:03:58 Recovery        4       4    1.0      0%     6 OK      
14:03:59 Recovery        5       5    1.0      0%     6 OK      
14:04:00 Recovery        5       5    1.0      0%     6 OK      
14:04:01 Recovery        5       5    1.0      0%     6 OK      

summary
pkts=8,304  syn=7,834  ack=470  alerts=1
first alert: syn=100/s ratio=9.1 hopen=89% srcs=101
```
