#!/bin/sh
#Create group

vaultaire create -g "Finance_Group" finance.company.com
vaultaire create -g "HR_Group" hr.company.com
vaultaire create -g "IT_Group" it.company.com
vaultaire create -g "Marketing_Group" marketing.company.com
vaultaire create -g "Legal_Group" legal.company.com

#Create user

vaultaire create -u alice company.com secret123 06/02/1992 alice@company.com
vaultaire create -u bob company.com strongpass 09/12/1988 bob@company.com
vaultaire create -u fiona company.com mypass321 08/07/1985 fiona@company.com
vaultaire create -u julie company.com loginme 10/09/1994 julie@company.com
vaultaire create -u charlie company.com admin987 03/09/1995 charlie@company.com
vaultaire create -u diana company.com pass456 01/07/1990 diana@company.com
vaultaire create -u eric company.com devpass99 30/01/1993 eric@company.com
vaultaire create -u george company.com testme! 12/11/1997 george@company.com
vaultaire create -u hannah company.com welcome1 04/02/1991 hannah@company.com
vaultaire create -u isaac company.com vault123 05/03/1989 isaac@company.com
vaultaire create -u proxmox_ldap_account company.com secret123 06/01/2004 

#add user to group
vaultaire add -u alice -g Finance_Group
vaultaire add -u bob -g HR_Group
vaultaire add -u fiona -g IT_Group
vaultaire add -u julie -g Marketing_Group
vaultaire add -u charlie -g Legal_Group
vaultaire add -u diana -g Finance_Group
vaultaire add -u eric -g IT_Group
vaultaire add -u george -g Marketing_Group
vaultaire add -u hannah -g HR_Group
vaultaire add -u isaac -g Legal_Group
vaultaire add -u proxmox_ldap_account -g IT_Group


#Create perm user

vaultaire create -p -u "LDAP_ReadOnly" Lecture_seule_LDAP
vaultaire create -p -u "LDAP_AdvancedSearch" Recherche_avancée_LDAP
vaultaire create -p -u "LDAP_WriteAccess" Ecriture_dans_LDAP
vaultaire create -p -u "LDAP_AdminPanel" Accès_admin_LDAP
vaultaire create -p -u "LDAP_Monitoring" Monitoring_et_logs_LDAP

#Add perm user to group
vaultaire add -gu Finance_Group -p LDAP_ReadOnly
vaultaire add -gu HR_Group -p LDAP_AdvancedSearch
vaultaire add -gu IT_Group -p LDAP_WriteAccess
vaultaire add -gu Marketing_Group -p LDAP_Monitoring
vaultaire add -gu Legal_Group -p LDAP_AdminPanel


#Create perm client
vaultaire create -p -c "Client_ReadOnly" not
vaultaire create -p -c "Client_AdminAccess" yes
vaultaire create -p -c "Client_AuditLogs" not
vaultaire create -p -c "Client_WriteOnly" not
vaultaire create -p -c "Client_FullAccess" yes

#Add perm client to group
vaultaire add -gc Finance_Group -p Client_ReadOnly
vaultaire add -gc HR_Group -p Client_AdminAccess
vaultaire add -gc IT_Group -p Client_FullAccess
vaultaire add -gc Marketing_Group -p Client_AuditLogs
vaultaire add -gc Legal_Group -p Client_WriteOnly

#create GPO
vaultaire create -gpo finance-env --cmd "export FINANCE_REPORT_PATH=/data/finance/reports; alias finreport='cat $FINANCE_REPORT_PATH/latest_report.txt'"
vaultaire create -gpo finance-security --cmd "export HISTCONTROL=ignoreboth; alias lock='gnome-screensaver-command -l'"

vaultaire create -gpo hr-calendar --cmd "alias calhr='curl -s https://company.com/api/hr/calendar | jq '.' '"
vaultaire create -gpo hr-notify --cmd "export HR_NOTIFICATION_LEVEL=high; alias notifyhr='echo \"Check your HR notifications!\"'"

vaultaire create -gpo it-docker --cmd "alias dclean='docker system prune -af --volumes'"
vaultaire create -gpo it-monitoring --cmd "alias sysmon='top -c | head -20'"

vaultaire create -gpo marketing-stats --cmd "alias mkstats='curl -s https://api.marketing.company.com/stats | jq '.' '"
vaultaire create -gpo marketing-update --cmd "alias mkupdate='git -C /srv/marketing-website pull origin main && systemctl reload nginx'"

vaultaire create -gpo legal-checklist --cmd "alias legaldoc='cat /srv/legal/checklist.md'"
vaultaire create -gpo legal-report --cmd "alias legalreport='curl -s https://legal.company.com/api/reports/latest'"

vaultaire add -gpo finance-env -p Finance_Group
vaultaire add -gpo finance-security -p Finance_Group

vaultaire add -gpo hr-calendar -p HR_Group
vaultaire add -gpo hr-notify -p HR_Group

vaultaire add -gpo it-docker -p IT_Group
vaultaire add -gpo it-monitoring -p IT_Group

vaultaire add -gpo marketing-stats -p Marketing_Group
vaultaire add -gpo marketing-update -p Marketing_Group

vaultaire add -gpo legal-checklist -p Legal_Group
vaultaire add -gpo legal-report -p Legal_Group
