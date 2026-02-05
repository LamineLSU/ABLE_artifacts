rule EvasionCheck  
{  
    meta:  
        description = "Detects evasion checks via specific control flow patterns"  
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:  
        $a = { 8B EC E8 D1 21 00 00 } // Call to check function  
        $b = { 8B FF 84 C0 74 20 }    // Test al, al + je  
        $c = { C1 E8 08 A8 01 75 10 } // Test al, 01h + jne  
    condition:  
        all of ($a, $b, $c)  
}