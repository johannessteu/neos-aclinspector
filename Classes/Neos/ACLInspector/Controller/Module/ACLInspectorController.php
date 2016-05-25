<?php
namespace Neos\ACLInspector\Controller\Module;

/*
 * This file is part of the Neos.ACLInspector package.
 */

use Neos\ACLInspector\Dto\ACLCheckerDto;
use Neos\ACLInspector\Service\ACLCheckerService;
use TYPO3\Flow\Annotations as Flow;
use TYPO3\Flow\Security\Policy\PolicyService;
use TYPO3\Neos\Controller\Module\AbstractModuleController;

class ACLInspectorController extends AbstractModuleController
{

    /**
     * @Flow\Inject
     * @var ACLCheckerService
     */
    protected $aclCheckService;

    /**
     * @Flow\Inject
     * @var PolicyService
     */
    protected $policyService;

    /**
     * @return void
     */
    public function indexAction(ACLCheckerDto $dto = null)
    {
        if ($dto !== null) {
            $nodes = $this->aclCheckService->resolveDto($dto);
        } else {
            $nodes = [];
        }

        $this->view->assignMultiple(
            [
                'dto' => $dto,
                'nodes' => $nodes,
                'roles' => $this->policyService->getRoles()
            ]
        );
    }

}
