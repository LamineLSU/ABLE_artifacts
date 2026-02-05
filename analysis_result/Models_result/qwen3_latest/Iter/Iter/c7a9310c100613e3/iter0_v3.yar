rule EvasionCheck1
{
    meta:
        description = "Detects a malicious code pattern that checks if AX is not equal to 1, leading to an exit."
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 66 83 F8 01 75 ?? }
    condition:
        $a
}