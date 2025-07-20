document.addEventListener('DOMContentLoaded', () => {
    const toastEl = document.getElementById('toast');
    const toast = new bootstrap.Toast(toastEl);
    const keyError = document.getElementById('keyError');
    const reissueError = document.getElementById('reissueError');
    const editUserError = document.getElementById('editUserError');
    const editDocError = document.getElementById('editDocError');

    // Show toast notification
    function showToast(message, isError = false) {
        toastEl.querySelector('.toast-body').textContent = message;
        toastEl.classList.toggle('bg-danger-subtle', isError);
        toastEl.classList.toggle('bg-success-subtle', !isError);
        toast.show();
    }

    // Create and trigger file download
    function triggerFileDownload(data, filename, mimeType) {
        const blob = new Blob([data], { type: mimeType });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
    }

    // Login Form Submission
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(loginForm);
            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    body: formData
                });
                const data = await response.json();
                if (data.success) {
                    showToast('Login successful!');
                    window.location.href = data.redirect;
                } else {
                    showToast(data.message, true);
                }
            } catch (error) {
                showToast('An error occurred during login', true);
            }
        });
    }

    // Register Form Submission
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(registerForm);
            try {
                const response = await fetch('/register', {
                    method: 'POST',
                    body: formData
                });
                const data = await response.json();
                showToast(data.message, !data.success);
                if (data.success) {
                    registerForm.reset();
                }
            } catch (error) {
                showToast('An error occurred during registration', true);
            }
        });
    }

    // Upload Form Submission
    const uploadForm = document.getElementById('uploadForm');
    if (uploadForm) {
        uploadForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(uploadForm);
            const progressBar = document.getElementById('uploadProgress');
            try {
                const response = await fetch('/upload', {
                    method: 'POST',
                    body: formData
                });
                const data = await response.json();
                showToast(data.message, !data.success);
                if (data.success) {
                    uploadForm.reset();
                    progressBar.style.width = '0%';
                    progressBar.setAttribute('aria-valuenow', 0);
                    setTimeout(() => window.location.reload(), 1000);
                }
            } catch (error) {
                showToast('An error occurred during upload', true);
            }
        });
    }

    // Sign Document
    const signForm = document.getElementById('signForm');
    const signModal = new bootstrap.Modal(document.getElementById('signModal'));
    const signButtons = document.querySelectorAll('.sign-btn');
    signButtons.forEach(button => {
        button.addEventListener('click', () => {
            document.getElementById('signDocId').value = button.dataset.docId;
            signModal.show();
        });
    });

    
    if (signForm) {
        signForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(signForm);
            const docId = document.getElementById('signDocId').value;
            try {
                const response = await fetch(`/sign/${docId}`, {
                    method: 'POST',
                    body: formData
                });
                const data = await response.json();
                showToast(data.message, !data.success);
                if (data.success) {
                    signForm.reset();
                    signModal.hide();
                    setTimeout(() => window.location.reload(), 1000);
                }
            } catch (error) {
                showToast('An error occurred during signing', true);
            }
        });
    }

    // Verify Document
    const verifyButtons = document.querySelectorAll('.verify-btn');
    verifyButtons.forEach(button => {
        button.addEventListener('click', async () => {
            try {
                const response = await fetch(`/verify/${button.dataset.docId}`, {
                    method: 'POST'
                });
                const data = await response.json();
                showToast(data.message, !data.success);
            } catch (error) {
                showToast('An error occurred during verification', true);
            }
        });
    });

    // Download Secret Key
    const privateKeyForm = document.getElementById('privateKeyForm');
    const secretKeyModal = new bootstrap.Modal(document.getElementById('secretKeyModal'));
    if (privateKeyForm) {
        privateKeyForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            keyError.classList.add('d-none');
            keyError.textContent = '';
            const formData = new FormData(privateKeyForm);
            try {
                const response = await fetch('/download_private_key', {
                    method: 'POST',
                    body: formData
                });
                if (!response.ok) {
                    const data = await response.json();
                    keyError.textContent = data.message;
                    keyError.classList.remove('d-none');
                    showToast(data.message, true);
                    return;
                }
                const filename = response.headers.get('Content-Disposition')?.match(/filename="(.+)"/)?.[1] || 'secret_key.pem';
                const blob = await response.blob();
                triggerFileDownload(blob, filename, 'application/x-pem-file');
                showToast('Secret key downloaded successfully!');
                privateKeyForm.reset();
                secretKeyModal.hide();
                setTimeout(() => window.location.reload(), 1000);
            } catch (error) {
                keyError.textContent = 'An error occurred during secret key download';
                keyError.classList.remove('d-none');
                showToast('An error occurred during secret key download', true);
            }
        });
    }

    // Reissue Certificate
    const reissueCertForm = document.getElementById('reissueCertForm');
    const reissueCertModal = new bootstrap.Modal(document.getElementById('reissueCertModal'));
    if (reissueCertForm) {
        reissueCertForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            reissueError.classList.add('d-none');
            reissueError.textContent = '';
            const formData = new FormData(reissueCertForm);
            try {
                const response = await fetch('/reissue_certificate', {
                    method: 'POST',
                    body: formData
                });
                const data = await response.json();
                if (data.success) {
                    showToast(data.message);
                    reissueCertForm.reset();
                    reissueCertModal.hide();
                    setTimeout(() => window.location.reload(), 1000);
                } else {
                    reissueError.textContent = data.message;
                    reissueError.classList.remove('d-none');
                    showToast(data.message, true);
                }
            } catch (error) {
                reissueError.textContent = 'An error occurred during certificate reissue';
                reissueError.classList.remove('d-none');
                showToast('An error occurred during certificate reissue', true);
            }
        });
    }

    // Edit User
    const editUserForm = document.getElementById('editUserForm');
    const editUserModal = new bootstrap.Modal(document.getElementById('editUserModal'));
    const editUserButtons = document.querySelectorAll('.edit-user-btn');
    editUserButtons.forEach(button => {
        button.addEventListener('click', () => {
            document.getElementById('editUserId').value = button.dataset.userId;
            document.getElementById('editUsername').value = button.dataset.username;
            document.getElementById('editEmail').value = button.dataset.email;
            document.getElementById('editRole').value = button.dataset.role;
            editUserError.classList.add('d-none');
            editUserModal.show();
        });
    });

    if (editUserForm) {
        editUserForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            editUserError.classList.add('d-none');
            const formData = new FormData(editUserForm);
            const userId = document.getElementById('editUserId').value;
            try {
                const response = await fetch(`/admin/edit_user/${userId}`, {
                    method: 'POST',
                    body: formData
                });
                const data = await response.json();
                if (data.success) {
                    showToast(data.message);
                    editUserForm.reset();
                    editUserModal.hide();
                    setTimeout(() => window.location.reload(), 1000);
                } else {
                    editUserError.textContent = data.message;
                    editUserError.classList.remove('d-none');
                    showToast(data.message, true);
                }
            } catch (error) {
                editUserError.textContent = 'An error occurred during user update';
                editUserError.classList.remove('d-none');
                showToast('An error occurred during user update', true);
            }
        });
    }

    // Delete User
    const deleteUserButtons = document.querySelectorAll('.delete-user-btn');
    deleteUserButtons.forEach(button => {
        button.addEventListener('click', async () => {
            if (confirm(`Are you sure you want to delete user ${button.dataset.username}?`)) {
                try {
                    const response = await fetch(`/admin/delete_user/${button.dataset.userId}`, {
                        method: 'POST'
                    });
                    const data = await response.json();
                    showToast(data.message, !data.success);
                    if (data.success) {
                        setTimeout(() => window.location.reload(), 1000);
                    }
                } catch (error) {
                    showToast('An error occurred during user deletion', true);
                }
            }
        });
    });

    // Edit Document
    const editDocForm = document.getElementById('editDocForm');
    const editDocModal = new bootstrap.Modal(document.getElementById('editDocModal'));
    const editDocButtons = document.querySelectorAll('.edit-doc-btn');
    editDocButtons.forEach(button => {
        button.addEventListener('click', () => {
            document.getElementById('editDocId').value = button.dataset.docId;
            document.getElementById('editFilename').value = button.dataset.filename;
            editDocError.classList.add('d-none');
            editDocModal.show();
        });
    });

    if (editDocForm) {
        editDocForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            editDocError.classList.add('d-none');
            const formData = new FormData(editDocForm);
            const docId = document.getElementById('editDocId').value;
            try {
                const response = await fetch(`/admin/edit_document/${docId}`, {
                    method: 'POST',
                    body: formData
                });
                const data = await response.json();
                if (data.success) {
                    showToast(data.message);
                    editDocForm.reset();
                    editDocModal.hide();
                    setTimeout(() => window.location.reload(), 1000);
                } else {
                    editDocError.textContent = data.message;
                    editDocError.classList.remove('d-none');
                    showToast(data.message, true);
                }
            } catch (error) {
                editDocError.textContent = 'An error occurred during document update';
                editDocError.classList.remove('d-none');
                showToast('An error occurred during document update', true);
            }
        });
    }

    // Delete Document
    const deleteDocButtons = document.querySelectorAll('.delete-doc-btn');
    deleteDocButtons.forEach(button => {
        button.addEventListener('click', async () => {
            if (confirm(`Are you sure you want to delete document ${button.dataset.filename}?`)) {
                try {
                    const response = await fetch(`/admin/delete_document/${button.dataset.docId}`, {
                        method: 'POST'
                    });
                    const data = await response.json();
                    showToast(data.message, !data.success);
                    if (data.success) {
                        setTimeout(() => window.location.reload(), 1000);
                    }
                } catch (error) {
                    showToast('An error occurred during document deletion', true);
                }
            }
        });
    });
});