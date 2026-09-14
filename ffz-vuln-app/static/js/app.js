// AcademicHub — scripts do cliente

// Fechar alertas ao clicar
document.querySelectorAll('.alert').forEach(function (el) {
  el.style.cursor = 'pointer';
  el.title = 'Clique para fechar';

  el.addEventListener('click', function () {
    el.remove();
  });
});


// VULN DOM XSS:
// parâmetro "notificacao" da URL processado com eval()
(function () {
  var params = new URLSearchParams(
    window.location.search
  );

  var notif = params.get('notificacao');

  if (notif) {
    try {
      // Intencionalmente inseguro:
      // eval() em entrada controlada pelo usuário
      eval(notif);
    } catch (e) {
      // Ignora erro propositalmente
    }
  }
})();
