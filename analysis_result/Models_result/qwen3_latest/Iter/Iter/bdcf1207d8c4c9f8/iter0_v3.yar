rule Bypass_CRT_Exit
{
    meta:
        description = "Detects bypass of CRT exit function (e.g., ExitProcess)"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { FF 75 08 E8 ?? ?? ?? ?? }
    condition:
        $a
}