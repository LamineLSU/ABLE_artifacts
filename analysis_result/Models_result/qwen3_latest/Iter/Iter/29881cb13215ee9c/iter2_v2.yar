rule TargetExitSequence  
{  
    meta:  
        description = "Detects the specific exit sequence in the target sample"  
    strings:  
        $a = { 53 FF 15 ?? ?? ?? ?? }  
    condition:  
        $a  
}