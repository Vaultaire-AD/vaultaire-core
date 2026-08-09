/* ====================================================================
 * Tests du module vlt_picker
 * ====================================================================
 *
 * Lancement :  ./run_tests.sh   (depuis web_packet/sso_WEB_page/tests/)
 *
 * Le module est chargé dans un DOM jsdom et piloté par de vrais
 * événements : ni fonction interne appelée directement, ni état inspecté
 * en douce. Ce qui est vérifié est donc ce qu'un navigateur ferait.
 *
 * Ce qui compte le plus ici, et qui n'est pas évident :
 *
 *   - le <select> doit rester DANS le formulaire après enrichissement,
 *     sans quoi rien n'est plus soumis et l'écran paraît fonctionner ;
 *   - Entrée dans le champ de recherche ne doit pas soumettre le
 *     formulaire, sinon chercher un utilisateur déclencherait « Ajouter »
 *     avec l'ancienne valeur ;
 *   - « Tout cocher » porte sur les options FILTRÉES et non sur toutes ;
 *   - destroy() doit rendre un <select> intact, toujours dans son <form>.
 * ==================================================================== */

const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

const js = fs.readFileSync(
  path.join(__dirname, '..', 'static', 'vlt_picker.js'), 'utf8');

const html = `<!DOCTYPE html><html><body>
<form id="f" action="/admin/groups" method="post">
  <input type="hidden" name="action" value="add_user">
  <select name="username" data-vlt-picker data-placeholder="Choisir un utilisateur">
    <option value="alice">alice</option>
    <option value="bob">bob</option>
    <option value="Céline">Céline</option>
    <option value="dave">dave</option>
    <option value="eve">eve</option>
    <option value="frank">frank</option>
    <option value="grace">grace</option>
    <option value="heidi">heidi</option>
    <option value="ivan">ivan</option>
  </select>
</form>
<form id="g">
  <select name="perm" data-vlt-picker multiple>
    <option value="p1" data-tags="admin">web_admin</option>
    <option value="p2" data-tags="standard">read_only</option>
    <option value="p3" data-tags="admin">super_admin</option>
  </select>
</form>
<form id="h"><select name="court" data-vlt-picker><option>a</option><option>b</option></select></form>
</body></html>`;

const dom = new JSDOM(html, { runScripts: 'outside-only', pretendToBeVisual: true });
const { window } = dom;
window.eval(js);
// jsdom laisse readyState a 'loading' : on declenche l'init comme le ferait le navigateur
window.VltPicker.init(window.document);
const D = window.document;

let ko = 0;
function ok(cond, label) {
  console.log((cond ? '  OK   ' : '  ECHEC') + '  ' + label);
  if (!cond) ko++;
}

// --- 1. initialisation
const sel = D.querySelector('select[name=username]');
const pick = sel.closest('.vlt-picker');
ok(!!pick, 'enveloppe construite');
ok(sel.parentNode === pick, 'le <select> reste dans l enveloppe (donc dans le <form>)');
ok(sel.closest('form') !== null, 'le <select> est toujours soumis par le formulaire');
ok(sel.classList.contains('vlt-picker-native'), 'classe de masquage posee par le JS');
ok(D.querySelectorAll('.vlt-picker').length === 3, '3 widgets construits');

// --- 2. etat initial : la premiere option reste selectionnee (comportement natif)
ok(sel.value === 'alice', 'valeur initiale inchangee : ' + sel.value);
ok(pick.querySelector('.vlt-picker-single').textContent === 'alice', 'bouton affiche alice');

// --- 3. ouverture
const ctl = pick.querySelector('.vlt-picker-control');
ok(ctl.type === 'button', 'le bouton ne soumet pas le formulaire');
ctl.dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
ok(pick.classList.contains('is-open'), 'panneau ouvert');
ok(!pick.querySelector('.vlt-picker-panel').hidden, 'panneau visible');
ok(pick.querySelectorAll('.vlt-picker-option').length === 9, '9 options rendues');

// --- 4. champ de recherche : present au-dela du seuil, absent en deca
ok(!pick.querySelector('.vlt-picker-search').hidden, 'recherche affichee (9 options)');
const court = D.querySelector('select[name=court]').closest('.vlt-picker');
ok(court.querySelector('.vlt-picker-search').hidden, 'recherche masquee (2 options)');

// --- 5. recherche insensible aux accents
const champ = pick.querySelector('.vlt-picker-input');
champ.value = 'celine';
champ.dispatchEvent(new window.Event('input', { bubbles: true }));
let vis = [...pick.querySelectorAll('.vlt-picker-option .vlt-picker-label')].map(e => e.textContent);
ok(vis.length === 1 && vis[0] === 'Céline', 'recherche "celine" trouve "Céline" -> ' + JSON.stringify(vis));
ok(pick.querySelector('.vlt-picker-label mark') !== null, 'occurrence surlignee');

// --- 6. selection a la souris -> ecrite dans le <select>, panneau ferme
let changes = 0;
sel.addEventListener('change', () => changes++);
pick.querySelector('.vlt-picker-option').dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
ok(sel.value === 'Céline', 'select mis a jour -> ' + sel.value);
ok(changes === 1, 'evenement change emis une fois');
ok(!pick.classList.contains('is-open'), 'panneau referme apres choix (mono)');

// --- 7. clavier : Entree ne soumet pas le formulaire
let submits = 0;
D.getElementById('f').addEventListener('submit', e => { submits++; e.preventDefault(); });
ctl.dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
const champ2 = pick.querySelector('.vlt-picker-input');
champ2.value = 'bob';
champ2.dispatchEvent(new window.Event('input', { bubbles: true }));
champ2.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true }));
ok(submits === 0, 'Entree ne soumet pas le formulaire');
ok(sel.value === 'bob', 'Entree choisit la ligne active -> ' + sel.value);

// --- 8. Echap referme
ctl.dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
pick.querySelector('.vlt-picker-input').dispatchEvent(
  new window.KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }));
ok(!pick.classList.contains('is-open'), 'Echap referme');

// --- 9. mode multiple + filtres + tout cocher
const selM = D.querySelector('select[name=perm]');
const pickM = selM.closest('.vlt-picker');
ok(pickM.classList.contains('vlt-picker--multiple'), 'mode multiple detecte');
const chips = [...pickM.querySelectorAll('.vlt-picker-chip')].map(c => c.textContent);
ok(chips.length === 2 && chips.join(',') === 'admin,standard', 'filtres deduits de data-tags -> ' + chips);
pickM.querySelector('.vlt-picker-control').dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
pickM.querySelector('.vlt-picker-chip[data-tag=admin]').dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
ok(pickM.querySelectorAll('.vlt-picker-option').length === 2, 'filtre admin -> 2 lignes');
pickM.querySelector('.vlt-picker-bulk-btn[data-act=all]').dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
const choisies = [...selM.selectedOptions].map(o => o.value);
ok(choisies.length === 2 && choisies.join(',') === 'p1,p3', 'tout cocher porte sur le filtre -> ' + choisies);
ok(pickM.classList.contains('is-open'), 'panneau reste ouvert en multiple');
ok(pickM.querySelectorAll('.vlt-picker-pill').length === 2, '2 jetons dans le bouton');
pickM.querySelector('.vlt-picker-bulk-btn[data-act=none]').dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
ok([...selM.selectedOptions].length === 0, 'effacer decoche tout');

// --- 10. destroy rend la main au natif
window.VltPicker.destroy(sel);
ok(!sel.classList.contains('vlt-picker-native'), 'destroy : classe retiree');
ok(sel.closest('.vlt-picker') === null, 'destroy : enveloppe supprimee');
ok(sel.closest('form') !== null, 'destroy : le select est toujours dans le formulaire');

// --- 11. idempotence
window.VltPicker.init(D);
ok(D.querySelectorAll('.vlt-picker').length === 3, 'init rejoue ne duplique pas');

console.log(ko === 0 ? '\nTOUS LES TESTS PASSENT' : '\n' + ko + ' ECHEC(S)');
process.exit(ko ? 1 : 0);
