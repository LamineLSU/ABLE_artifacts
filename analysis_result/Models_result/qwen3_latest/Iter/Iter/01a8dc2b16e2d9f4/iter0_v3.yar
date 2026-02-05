rule MaliciousCodePattern
{
    meta:
        description = "Detects code patterns leading to early exit in malicious behavior"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"

    strings:
        $a = { 85 C0 75 0D E8 ?? ?? ?? ?? }  // First test and jump, followed by call
        $b = { 85 C0 74 0F 8B 45 ?? }         // Second test and jump, followed by mov
        $c = { 53 E8 ?? ?? ?? ?? }           // Push ebx followed by call to ExitProcess

    condition:
        all of ($a, $b, $c)
}