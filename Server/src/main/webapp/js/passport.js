var passport = (function () {

  function idp_redirect(provider) {
    var form = document.forms.loginForm;
    form["loginForm:provider"].value = provider;
    form["loginForm:loginPassportButton"].click();
  }

  function dynamic_link(provider, logo_img, name) {
    name = name ? name : provider;
    if (logo_img == null) {
      logo_img = "/oxauth/img/glu_icon.png"
    } else if (!logo_img.startsWith("http")) {
      logo_img = "/oxauth/auth/passport/" + logo_img
    }

    imgMarkup = '<img alt="' + name
      + '" onclick="passport.idp_redirect(\'' + provider
      + '\')" src="' + logo_img + '"></img>';
    leftMarkup = '<div onclick="passport.idp_redirect(\'' + provider
      + '\')" class="provider-img">' + imgMarkup + '</div>';
    $('#listProviders').append(
      '<div class="row provider ' + provider + '">' + leftMarkup + '</div>');
  }



  return {
    idp_redirect: idp_redirect,
    dynamic_link: dynamic_link
  }

})();
