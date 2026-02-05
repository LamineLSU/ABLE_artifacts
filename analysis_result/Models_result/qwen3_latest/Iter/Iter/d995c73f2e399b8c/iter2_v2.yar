rule MaliciousPattern
{
    meta:
        description = "Detects patterns of stack manipulation and indirect calls often seen in obfuscated code."
        cape_options = "bp0=$c+0,action0=skip,count=0"

    strings:
        $a = /call edx/  
        $b = /call 0x418DB0/  
        $c = { 83 C4 04 } (3 of them)

    condition:
        all of ($a, $b, $c)
}