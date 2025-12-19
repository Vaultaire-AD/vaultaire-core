#!/bin/sh
#Create group

/opt/vaultaire/vaultaire_cli create -g "Finance_Group" finance.company.com
/opt/vaultaire/vaultaire_cli create -g "HR_Group" hr.company.com
/opt/vaultaire/vaultaire_cli create -g "IT_Group" it.company.com
/opt/vaultaire/vaultaire_cli create -g "IT_Group-Infra" infra.it.company.com
/opt/vaultaire/vaultaire_cli create -g "Marketing_Group" marketing.company.com
/opt/vaultaire/vaultaire_cli create -g "Legal_Group" legal.company.com

#Create user

/opt/vaultaire/vaultaire_cli create -u alice.feur company.com secret123 06/02/1992
/opt/vaultaire/vaultaire_cli create -u bob company.com strongpass 09/12/1988
/opt/vaultaire/vaultaire_cli create -u fiona company.com mypass321 08/07/1985
/opt/vaultaire/vaultaire_cli create -u julie company.com loginme 10/09/1994
/opt/vaultaire/vaultaire_cli create -u charlie company.com admin987 03/09/1995 charlie lachocolaterie
/opt/vaultaire/vaultaire_cli create -u diana company.com pass456 01/07/1990 
/opt/vaultaire/vaultaire_cli create -u eric company.com devpass99 30/01/1993 
/opt/vaultaire/vaultaire_cli create -u george company.com testme! 12/11/1997 
/opt/vaultaire/vaultaire_cli create -u hannah company.com ff 04/02/1991 
/opt/vaultaire/vaultaire_cli create -u isaac company.com vault123 05/03/1989 
/opt/vaultaire/vaultaire_cli create -u proxmox_ldap_account company.com secret123 06/01/2004 proxmox Account

#add user to group
/opt/vaultaire/vaultaire_cli add -u alice -g Finance_Group
/opt/vaultaire/vaultaire_cli add -u bob -g HR_Group
/opt/vaultaire/vaultaire_cli add -u fiona -g IT_Group
/opt/vaultaire/vaultaire_cli add -u julie -g Marketing_Group
/opt/vaultaire/vaultaire_cli add -u charlie -g Legal_Group
/opt/vaultaire/vaultaire_cli add -u diana -g Finance_Group
/opt/vaultaire/vaultaire_cli add -u eric -g IT_Group
/opt/vaultaire/vaultaire_cli add -u eric -g IT_Group-Infra
/opt/vaultaire/vaultaire_cli add -u george -g Marketing_Group
/opt/vaultaire/vaultaire_cli add -u hannah -g HR_Group
/opt/vaultaire/vaultaire_cli add -u isaac -g Legal_Group
/opt/vaultaire/vaultaire_cli add -u proxmox_ldap_account -g IT_Group


#Create perm user

/opt/vaultaire/vaultaire_cli create -p -u "LDAP_ReadOnly" Lecture_seule_LDAP
/opt/vaultaire/vaultaire_cli create -p -u "LDAP_AdvancedSearch" Recherche_avancée_LDAP
/opt/vaultaire/vaultaire_cli create -p -u "LDAP_WriteAccess" Ecriture_dans_LDAP
/opt/vaultaire/vaultaire_cli create -p -u "LDAP_AdminPanel" Accès_admin_LDAP
/opt/vaultaire/vaultaire_cli create -p -u "LDAP_Monitoring" Monitoring_et_logs_LDAP

#Add perm user to group
/opt/vaultaire/vaultaire_cli add -gu Finance_Group -p LDAP_ReadOnly
/opt/vaultaire/vaultaire_cli add -gu HR_Group -p LDAP_AdvancedSearch
/opt/vaultaire/vaultaire_cli add -gu IT_Group -p LDAP_WriteAccess
/opt/vaultaire/vaultaire_cli add -gu Marketing_Group -p LDAP_Monitoring
/opt/vaultaire/vaultaire_cli add -gu Legal_Group -p LDAP_AdminPanel


#Create perm client
/opt/vaultaire/vaultaire_cli create -p -c "Client_ReadOnly" not
/opt/vaultaire/vaultaire_cli create -p -c "Client_AdminAccess" yes
/opt/vaultaire/vaultaire_cli create -p -c "Client_AuditLogs" not
/opt/vaultaire/vaultaire_cli create -p -c "Client_WriteOnly" not
/opt/vaultaire/vaultaire_cli create -p -c "Client_FullAccess" yes

#Add perm client to group
/opt/vaultaire/vaultaire_cli add -gc Finance_Group -p Client_ReadOnly
/opt/vaultaire/vaultaire_cli add -gc HR_Group -p Client_AdminAccess
/opt/vaultaire/vaultaire_cli add -gc IT_Group -p Client_FullAccess
/opt/vaultaire/vaultaire_cli add -gc Marketing_Group -p Client_AuditLogs
/opt/vaultaire/vaultaire_cli add -gc Legal_Group -p Client_WriteOnly

#create GPO
/opt/vaultaire/vaultaire_cli create -gpo finance-env --cmd "export FINANCE_REPORT_PATH=/data/finance/reports; alias finreport='cat $FINANCE_REPORT_PATH/latest_report.txt'"
/opt/vaultaire/vaultaire_cli create -gpo finance-security --cmd "export HISTCONTROL=ignoreboth; alias lock='gnome-screensaver-command -l'"

/opt/vaultaire/vaultaire_cli create -gpo hr-calendar --cmd "alias calhr='curl -s https://company.com/api/hr/calendar | jq '.' '"
/opt/vaultaire/vaultaire_cli create -gpo hr-notify --cmd "export HR_NOTIFICATION_LEVEL=high; alias notifyhr='echo \"Check your HR notifications!\"'"

/opt/vaultaire/vaultaire_cli create -gpo it-docker --cmd "alias dclean='docker system prune -af --volumes'"
/opt/vaultaire/vaultaire_cli create -gpo it-monitoring --cmd "alias sysmon='top -c | head -20'"

/opt/vaultaire/vaultaire_cli create -gpo marketing-stats --cmd "alias mkstats='curl -s https://api.marketing.company.com/stats | jq '.' '"
/opt/vaultaire/vaultaire_cli create -gpo marketing-update --cmd "alias mkupdate='git -C /srv/marketing-website pull origin main && systemctl reload nginx'"

/opt/vaultaire/vaultaire_cli create -gpo legal-checklist --cmd "alias legaldoc='cat /srv/legal/checklist.md'"
/opt/vaultaire/vaultaire_cli create -gpo legal-report --cmd "alias legalreport='curl -s https://legal.company.com/api/reports/latest'"

/opt/vaultaire/vaultaire_cli add -gpo finance-env -p Finance_Group
/opt/vaultaire/vaultaire_cli add -gpo finance-security -p Finance_Group

/opt/vaultaire/vaultaire_cli add -gpo hr-calendar -p HR_Group
/opt/vaultaire/vaultaire_cli add -gpo hr-notify -p HR_Group

/opt/vaultaire/vaultaire_cli add -gpo it-docker -p IT_Group
/opt/vaultaire/vaultaire_cli add -gpo it-monitoring -p IT_Group

/opt/vaultaire/vaultaire_cli add -gpo marketing-stats -p Marketing_Group
/opt/vaultaire/vaultaire_cli add -gpo marketing-update -p Marketing_Group

/opt/vaultaire/vaultaire_cli add -gpo legal-checklist -p Legal_Group
/opt/vaultaire/vaultaire_cli add -gpo legal-report -p Legal_Group

/opt/vaultaire/vaultaire_cli update -pu LDAP_WriteAccess search yes

/opt/vaultaire/vaultaire_cli create -u keycloak.ldap company.com it4 07/06/2025
/opt/vaultaire/vaultaire_cli create -g ALL company.com
/opt/vaultaire/vaultaire_cli add -gu ALL -p LDAP_WriteAccess
#ldap://vaultaire-ad.vaultaire.svc.cluster.local
#ldap://vaultaire-ad.vaultaire.svc.cluster.local
#dc=it,dc=company,dc=com
