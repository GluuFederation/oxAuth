var revocation = (function () {

    function copy() {
        var text = document.getElementById('loginForm:text-to-copy');
        let text_to_copy = '';

        for (var i = 0; i < text.children.length; i++) {
            var child = text.children[i];
            console.log(child)
            text_to_copy += child.innerText + '\n';
        }

        navigator.clipboard.writeText(text_to_copy);
    }

    function mouseover() {
        var text = document.getElementById('loginForm:text-to-copy');
        text.classList.add("copied");
    }

    function mouseout() {
        var text = document.getElementById('loginForm:text-to-copy');
        text.classList.remove("copied");
    }

    return {
        copy: copy,
        mouseover: mouseover,
        mouseout: mouseout,
    }

})();
