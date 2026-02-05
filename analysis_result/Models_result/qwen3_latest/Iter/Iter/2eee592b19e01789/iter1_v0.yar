rule WindowsProcessControl
{
    meta:
        description = "Detects calls to Windows API functions related to process control"
        cape_options = "bp0=$terminate+0,action0=skip,bp1=$exit+0,action1=skip,bp2=$current+0,action2=skip,count=0"
        author = "Malware Analyst"
    
    strings:
        $terminate = { FF 15 1E 17 01 00 }
        $exit = { FF 15 3F 18 01 00 }
        $current = { FF 15 A9 16 01 00 }
    
    condition:
        all of them
}